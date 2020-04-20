from django.contrib import admin
from .models import User, Student
# from import_export import resources

admin.site.register(User)

class CustomModelAdmin(admin.ModelAdmin):
    def __init__(self, model, admin_site):
        self.list_display = [field.name for field in model._meta.fields]
        super(CustomModelAdmin, self).__init__(model, admin_site)


# class StudentResource(resources.ModelResource):

#     class Meta:
#         model = Student
#         fields = (
#             'student_id', 
#             'first_name', 
#             'last_name', 
#             'birth_date', 
#             'medical_condition',
#             'language',
#         )