from itertools import chain

from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.db.models import Q, F

from guardian.utils import get_identity

class ObjectPermissionChecker(object):
    """
    Generic object permissions checker class being the heart of
    ``django-guardian``.

    .. note::
       Once checked for single object, permissions are stored and we don't hit
       database again if another check is called for this object. This is great
       for templates, views or other request based checks (assuming we don't
       have hundreds of permissions on a single object as we fetch all
       permissions for checked object).

       On the other hand, if we call ``has_perm`` for perm1/object1, then we
       change permission state and call ``has_perm`` again for same
       perm1/object1 on same instance of ObjectPermissionChecker we won't see a
       difference as permissions are already fetched and stored within cache
       dictionary.
    """
    def __init__(self, user_or_group=None):
        """
        :param user_or_group: should be an ``User``, ``AnonymousUser`` or
          ``Group`` instance
        """
        self.user, self.group = get_identity(user_or_group)
        self._obj_perms_cache = {}

    def _execute_normal_user_query(self, obj=None, content_type=None, user=None):
        """
        Returns all permissions for a given user on a given object and content type
        """

        cursor = connection.cursor()

        query = """SELECT "auth_permission"."codename" FROM "auth_permission"
                 INNER JOIN "django_content_type" ON ("auth_permission"."content_type_id" = "django_content_type"."id") 
                 LEFT OUTER JOIN "guardian_groupobjectpermission" ON ("auth_permission"."id" = "guardian_groupobjectpermission"."permission_id") 
                 LEFT OUTER JOIN "auth_group" ON("guardian_groupobjectpermission"."group_id" = "auth_group"."id") 
                 LEFT OUTER JOIN "auth_user_groups" ON ("auth_group"."id" = "auth_user_groups"."group_id")
                 WHERE 
                 ("auth_permission"."content_type_id" = {0} AND 
                     (
                         "guardian_groupobjectpermission"."object_pk" = '{1}' AND 
                         "auth_user_groups"."user_id" = {2} AND
                         "guardian_groupobjectpermission"."content_type_id" = "auth_permission"."content_type_id"
                     )
                 )
                 UNION ALL
                 SELECT "auth_permission"."codename" FROM "auth_permission" 
                 INNER JOIN "django_content_type" ON ("auth_permission"."content_type_id" = "django_content_type"."id") 
                 LEFT OUTER JOIN "guardian_userobjectpermission" ON ("auth_permission"."id" = "guardian_userobjectpermission"."permission_id") 
                 WHERE 
                 ("auth_permission"."content_type_id" = {3} AND 
                     (
                        "guardian_userobjectpermission"."object_pk" = '{4}' AND
                        "guardian_userobjectpermission"."user_id" = {5} AND 
                        "guardian_userobjectpermission"."content_type_id" = "auth_permission"."content_type_id" 
                     )
                 )
                 """.format(content_type.id, obj.pk, user.id, content_type.id, obj.pk, user.id)

        cursor.execute(query)
        result = [row[0] for row in cursor.fetchall()]

        return result


    def has_perm(self, perm, obj):
        """
        Checks if user/group has given permission for object.

        :param perm: permission as string, may or may not contain app_label
          prefix (if not prefixed, we grab app_label from ``obj``)
        :param obj: Django model instance for which permission should be checked

        """
        perm = perm.split('.')[-1]
        if self.user and not self.user.is_active:
            return False
        elif self.user and self.user.is_superuser:
            return True
        return perm in self.get_perms(obj)

    def get_perms(self, obj):
        """
        Returns list of ``codename``'s of all permissions for given ``obj``.

        :param obj: Django model instance for which permission should be checked

        """
        ctype = ContentType.objects.get_for_model(obj)
        key = self.get_local_cache_key(obj)

        if not key in self._obj_perms_cache:
            if self.user and not self.user.is_active:
                return []
            elif self.user and self.user.is_superuser:
                perms = list(chain(*Permission.objects
                    .filter(content_type=ctype)
                    .values_list("codename")))
            elif self.user:
                # use custom query here to avoid poorly ORM produced queries
                perms = self._execute_normal_user_query(
                             obj=obj, user=self.user, content_type=ctype)
            else:
                perms = list(set(chain(*Permission.objects
                    .filter(content_type=ctype)
                    .filter(
                        groupobjectpermission__content_type=F('content_type'),
                        groupobjectpermission__group=self.group,
                        groupobjectpermission__object_pk=obj.pk)
                    .values_list("codename"))))
            self._obj_perms_cache[key] = perms
        return self._obj_perms_cache[key]

    def get_local_cache_key(self, obj):
        """
        Returns cache key for ``_obj_perms_cache`` dict.
        """
        ctype = ContentType.objects.get_for_model(obj)
        return (ctype.id, obj.pk)

