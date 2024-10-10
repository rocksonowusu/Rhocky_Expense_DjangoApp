from django.contrib import admin
from .models import(
    Expense,
    Category, 
    UserPreferences,
    UserIncome,
    Source
)

# Register your models here.
class ExpenseAdmin(admin.ModelAdmin):
    list_display=('amount', 'description', 'owner', 'category','date')
    search_fields =('description', 'category','date')
    list_per_page = 4
admin.site.register(Expense, ExpenseAdmin)
admin.site.register(Category)
admin.site.register(UserPreferences)
admin.site.register(UserIncome)
admin.site.register(Source)