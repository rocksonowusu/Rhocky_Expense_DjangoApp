from django.db import models
from django.contrib.auth.hashers import make_password
from django.utils.timezone import now
from django.contrib.auth.models import User



#user preferences model
class UserPreferences(models.Model):
    user = models.OneToOneField(to=User, on_delete=models.CASCADE)
    currency = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return str(self.user) + "'s preferences"

# authentication model
class Register(models.Model):
    username = models.CharField(max_length= 100)
    first_name = models.CharField(max_length= 100)
    last_name = models.CharField(max_length= 100)
    email= models.EmailField()
    password = models.CharField(max_length=100)

    def __str__(self):
        return self.first_name + self.last_name
    
    def set_password(self, raw_password):
        self.password = make_password(raw_password)


# Expense Model
class Expense(models.Model):
    amount = models.FloatField()
    date = models.DateField(default=now)
    description = models.TextField()
    owner = models.ForeignKey(to = User, on_delete= models.CASCADE)
    category = models.CharField(max_length=266)

    def __str__(self):
        return self.category

    class Meta:
        ordering:['date'] # type: ignore

class Category(models.Model):
    name = models.CharField(max_length=255)

    class Meta:
        verbose_name_plural='Categories'

    def __str__(self):
        return self.name

class UserIncome(models.Model):
    amount = models.FloatField()
    date = models.DateField(default = now)
    description = models.TextField(max_length= 300)
    owner = models.ForeignKey(to = User, on_delete = models.CASCADE)
    source = models.CharField(max_length = 256)
    def __str__(self):
        return self.source

    class Meta:
        ordering = ['-date']

class Source(models.Model):
    name = models.CharField(max_length=255)
    def __str__(self):
        return self.name