from django.shortcuts import render, redirect, get_object_or_404
from django.views import View
import json
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import EmailMessage
from validate_email import validate_email
from django.utils.encoding import force_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.contrib import auth
from django.urls import reverse
import threading
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .utils import (
    token_generator
)
#income import 
from .models import (
    UserIncome,
    Source,
)

#expense import
# from django.shortcuts import render,redirect 
from django.core.exceptions import ObjectDoesNotExist
# from django.contrib import messages
from django.views.decorators.cache import cache_control
from django.contrib.auth.decorators import  login_required
from django.core.paginator import Paginator
import json
from django.db.models import Sum
from .models import UserPreferences
# from userincome.models import UserIncome
import datetime
from .models import (
    Category,
    Expense,
    UserPreferences
)

#user preferences import
from django.conf import settings
import os
from django.db.models import Sum
from django.db.models.functions import ExtractMonth
from django.http import HttpResponse
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.platypus import Spacer



#userpreferences
@login_required(login_url='login')
def userindex(request):
    currency_data = []
    file_path = os.path.join(settings.BASE_DIR, 'currencies.json')

    # Getting data from file_path using "open" with encoding specified
    with open(file_path, 'r', encoding='utf-8') as json_file:
        data = json.load(json_file)

        for k, v in data.items():
            currency_data.append({'name': k, 'value': v})

    exists = UserPreferences.objects.filter(user=request.user).exists()

    user_preferences = None
    if exists:
        user_preferences = UserPreferences.objects.get(user=request.user)

    if request.method == 'GET':
        return render(request, 'preferences/index.html', {'currencies': currency_data})
    else:
        currency = request.POST['currency']
        if exists:
            user_preferences.currency = currency
            user_preferences.save()
        else:
            UserPreferences.objects.create(user=request.user, currency=currency)
        messages.success(request, 'Changes Saved')
        return render(request, 'preferences/index.html', {'currencies': currency_data})
# Create your views here.
@login_required(login_url='login')
def dashboard(request):
    if request.user.is_authenticated:
        try:
            currency = UserPreferences.objects.get(user=request.user).currency
        except ObjectDoesNotExist:
            messages.warning(request, 'Choose your currency')
            return redirect('preferences') 

        expenses = Expense.objects.all()
        income = UserIncome.objects.all()
        total_income_amount = income.aggregate(total=Sum('amount'))['total']
        currency = UserPreferences.objects.get(user=request.user).currency
        total_expense_amount = expenses.aggregate(total=Sum('amount'))['total']
        expense_categories = Expense.objects.values_list('category', flat=True).distinct()
        income_source = UserIncome.objects.values_list('source', flat=True).distinct()
        balance = total_income_amount - total_expense_amount

        if total_income_amount and total_expense_amount:
            percentage = round((total_expense_amount / total_income_amount ) * 100)
        else:
            percentage = 0

        context = {
            "expense_category": expense_categories,
            "income_source": income_source,
            "total_expense_amount": total_expense_amount,
            "total_income_amount": total_income_amount,
            "currency": currency,
            "balance" : balance,
            "percentage": percentage
        }
        return render(request, "dashboard.html", context)
    else:
        return redirect('login')

class EmailThreading(threading.Thread):
    def __init__(self, email): 
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send(fail_silently=False)

class UsernameValidation(View):
    def post(self,request):
        data = json.loads(request.body)
        username = data['username']

        if not str(username).isalnum():
            return JsonResponse({'username_error':'Invalid Username'}, status = 400)
       
        if User.objects.filter(username=username).exists():   # to check if username exist
            return JsonResponse({'username_error':'Username has already been taken, Choose another'}, status = 409)
        return JsonResponse({'username_valid':True})
    
class EmailValidation(View):
    def post(self,request):
        data = json.loads(request.body)
        email = data['email']

        if not validate_email(email):
            return JsonResponse({'email_error':'Email is Invalid'}, status = 400)
       
        if User.objects.filter(email=email).exists():   # to check if username exist
            return JsonResponse({'email_error':'Email has already been taken, Choose another'}, status = 409)
        return JsonResponse({'email_valid':True})
    


class RegistrationView(View):
    def get(self, request):
        return render(request, 'register.html')

    def post(self, request):
        # GET USER DATA
        # VALIDATE
        # Then create a user account.

        username = request.POST.get('username', '')
        email = request.POST.get('email', '')
        password = request.POST.get('password', '')

        context ={
            "fieldValues": request.POST
        }

        if not User.objects.filter(username=username).exists():
            if not User.objects.filter(email=email).exists():

                if not password:
                    # messages.error(request, "Password cannot be empty")
                    return render(request, 'register.html')

                if len(password) < 8:
                    messages.error(request, "Password too short" )
                    return render(request, 'register.html',context)

                user = User.objects.create_user(username=username, email=email)
                user.set_password(password)
                user.is_active = False
                user.save()

            #path to view
                #-getting domain we are on
                #-relative url  to verication
                #-encode uid
                #-token
                uidb64= urlsafe_base64_encode(force_bytes(user.pk))
                domain = get_current_site(request).domain
                link = reverse('activate', kwargs={'uidb64': uidb64, 'token': token_generator.make_token(user)})

                activate_url = 'http://'+domain+link

                email_body = 'Hello ' + user.username+ " Please use this link to verify your account\n" + activate_url
                email_subject = "Activate your Account"
                email = EmailMessage(
                    email_subject,
                    email_body,
                    "djangorockson@gmail.com",
                    [email],
                )
                EmailThreading(email).start()
                messages.success(request, "Account created successfully")
                return render(request, 'register.html')

        return render(request, 'register.html')

class VerificationView(View):
    def get(self, request, uidb64, token):

        try:
            id = force_bytes(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk = id)

            if not token_generator.check_token(user, token):
                return redirect('login'+'?message='+'User already activated')

            if user.is_active:
                return redirect('login')
            user.is_active = True
            user.save()
            messages.success(request, 'Account activated successfully')
            return redirect('login')
        except Exception as ex:
            pass

        return redirect('login') 
    
class LoginView(View):
    def get(self, request):
        return render(request, 'login.html')
    
    def post(self, request):
        username = request.POST['username']
        password = request.POST['password']

        if username and password:
            user = auth.authenticate(username = username, password = password)

            if user:
                if user.is_active:
                    auth.login(request, user)
                    messages.success(request, 'Welcome, '+ user.username +' You are now logged in')
                    return redirect('dashboard')
            
                messages.error(request, 'Account is not active, please check your mail ')
                return render(request, 'login.html')

            messages.error(request, 'Invalid credentials, Try again')
            return render(request, 'login.html')
        
        messages.error(request, 'Please fill all fields')
        return render(request, 'login.html')


class LogoutView(View):
    def post(self, request):
        auth.logout(request)
        messages.success(request, 'You have been logged out')
        return render(request, 'login.html')

class RequestPasswordResetEmail(View):
    def get(self, request):
        return render(request, 'reset_password.html')
    
    def post(self, request):
        email = request.POST['email']
        context ={
            'values': request.POST
        }
        if not validate_email(email):
            messages.error(request, "Please enter a valid email")
            return render(request, 'reset_password.html', context)

        
        current_site = get_current_site(request)
        user = get_object_or_404(User, email=email)

    
        email_contents = {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': PasswordResetTokenGenerator().make_token(user),
            }
        link = reverse('reset_user_password', kwargs={
                'uidb64': email_contents['uid'], 'token': email_contents['token']
            })  
        email_subject = 'Password Reset Instructions'
        reset_url = 'htpp://'+ current_site.domain+link

        email = EmailMessage(
                email_subject,
                'Hi there, Please click the link below to reset your password\n' + reset_url,
                'djangorockson@gmail.com',
                [email]
            )
        EmailThreading(email).start()
        messages.success(request, "We have sent you an email")
    
        return render(request, 'reset_password.html')
    
class CompletPasswordReset(View):
    def get(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token
        }

        try:
            user_id = force_bytes(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.info(request, "Password link is invalid. Please request a new one.")
                return render(request, 'reset_password.html')
        except Exception as e:
            messages.info(request, "Something went wrong. Please try again.")
            return render(request, "set_new_password.html", context)
        return render(request, "set_new_password.html", context)

    def post(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token
        }

        password = request.POST['password']
        password2 = request.POST['password2']
        
        if len(password) < 6:
            messages.error(request, "Password should be at least 6 characters long.")
            return render(request, "set_new_password.html", context)

        if password != password2:
            messages.error(request, "Passwords do not match.")
            return render(request, "set_new_password.html", context)

        try:
            user_id = force_bytes(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()
            messages.success(request, "Password reset successful. You can now login with your new password.")
            return redirect('login')
        except Exception as e:
            messages.error(request, "Something went wrong. Please try again.")
            return render(request, "set_new_password.html", context)
        # return render( request, "authentication/set_new_password.html",context)
   
   #expense view 
@login_required(login_url='login')
def search_expenses(request):
    if request.method == 'POST':
        search_str = json.loads(request.body).get('searchText')
        expenses = Expense.objects.filter(
            amount__icontains=search_str, owner=request.user
        ) | Expense.objects.filter(
            date__icontains=search_str, owner=request.user
        ) | Expense.objects.filter(
            category__icontains=search_str, owner=request.user
        ) | Expense.objects.filter(
            description__icontains=search_str, owner=request.user
        )
        
        data = list(expenses.values())
        return JsonResponse(data, safe=False)


@login_required(login_url='login')
def index(request):
 # Update this with the actual URL for setting preferences

    categories = Category.objects.all()
    expense = Expense.objects.filter(owner=request.user)
    paginator = Paginator(expense, 5)
    page_number = request.GET.get('page')
    page_obj = Paginator.get_page(paginator, page_number)

    context = {
            'expenses': expense,
            'page_obj': page_obj,
            'categories': categories,
        }

    return render(request, 'expense/index.html', context)
 
@login_required(login_url='login')
def add_expenses(request):
    categories = Category.objects.all()
    context = {
            'categories' :categories,
            'values': request.POST
        }
    if request.method=="GET":
        return render(request, 'expense/add_expenses.html', context)

    if request.method =="POST":
        amount = request.POST['amount']
        if not amount:
            messages.error(request, 'Amount required')
            return render(request, 'expense/add_expenses.html', context)

        description = request.POST['description']
        date = request.POST['expense_date']
        category = request.POST['category']
        if not description:
            messages.error(request, 'Description required')
            return render(request, 'expense/add_expenses.html', context)
        Expense.objects.create(owner=request.user, amount=amount, date=date, category=category, description=description)
        messages.success(request, 'Expense saved successfully')
        return redirect('expenses')
    
@login_required(login_url='login')
def expense_edit(request, id):
    expense = Expense.objects.get(pk=id)
    categories = Category.objects.all()
    context = {
        'expense': expense,
        'values': expense,
        'categories':categories
    }
    if request.method == "GET":
        return render(request, 'expense/expenses_edit.html', context)
    
    if request.method == "POST":
        amount = request.POST['amount']
        if not amount:
            messages.error(request, 'Amount required')
            return render(request, 'expense/expenses_edit.html', context)

        description = request.POST['description']
        date = request.POST['expense_date']
        category = request.POST['category']
        if not description:
            messages.error(request, 'Description required')
            return render(request, 'expense/edit_expense.html', context)
        expense.owner=request.user
        expense.amount=amount 
        expense.date=date 
        expense.category=category 
        expense.description=description
        expense.save()
        messages.success(request, 'Expense updated successfully')
        return redirect('expenses')
    return render(request, 'expense/expense_edit.html', context)

@login_required(login_url='login')    
def expense_delete(request, id):
    expense = Expense.objects.get(pk = id)
    expense.delete()
    messages.success(request, "Expense removed")
    return redirect('expenses')
  


def expense_income_summary(request):
    # Get current year
    current_year = datetime.date.today().year

    # Get total expenses for each month of the current year
    expense_summary = Expense.objects.filter(date__year=current_year) \
        .annotate(month=ExtractMonth('date')) \
        .values('month') \
        .annotate(total_expenses=Sum('amount')) \
        .order_by('month')

    # Get total income for each month of the current year
    income_summary = UserIncome.objects.filter(date__year=current_year) \
        .annotate(month=ExtractMonth('date')) \
        .values('month') \
        .annotate(total_income=Sum('amount')) \
        .order_by('month')

    # Prepare data for the chart
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]  # Assuming 1 represents January, 2 represents February, and so on
    expenses = [0] * 12
    income = [0] * 12

    for item in expense_summary:
        expenses[item['month'] - 1] = item['total_expenses']

    for item in income_summary:
        income[item['month'] - 1] = item['total_income']

    data = {
        'months': months,
        'expenses': expenses,
        'income': income
    }

    return JsonResponse(data)



def stats_view(request):
    # Call the expense_income_summary function to get the data
    summary_data_response = expense_income_summary(request)
    summary_data = json.loads(summary_data_response.content)  # Extract JSON data from the JsonResponse

    return render(request, 'expense/stats.html', {'summary_data': summary_data})


def search_income(request):
    if request.method == 'POST':
        search_str = json.loads(request.body).get('searchText')
        income = UserIncome.objects.filter(
            amount__istartswith=search_str, owner = request.user) | UserIncome.objects.filter(
            date__istartswith=search_str, owner = request.user) | UserIncome.objects.filter(
            source__icontains=search_str, owner = request.user) | UserIncome.objects.filter(
            description__icontains=search_str, owner = request.user)
        data = income.values()
        return JsonResponse(list(data), safe = False)



@login_required(login_url='login')
def incomeindex(request):
    if request.user.is_authenticated:
        sources = Source.objects.all()
        income = UserIncome.objects.filter(owner=request.user)
        paginator = Paginator(income, 5)
        page_number = request.GET.get('page')
        page_obj = Paginator.get_page(paginator,page_number)
        currency = UserPreferences.objects.get(user = request.user).currency
        context = {
            'income': income,
            'page_obj':page_obj,
            'currency':currency,
        }
        return render(request, 'income/index.html', context)
    else:
        return redirect('login')

@login_required(login_url='login')
def add_income(request):
    sources = Source.objects.all()
    context = {
            'sources' :sources,
            'values': request.POST
        }
    if request.method=="GET":
        return render(request, 'income/add_income.html', context)

    if request.method =="POST":
        amount = request.POST['amount']
        if not amount:
            messages.error(request, 'Amount required')
            return render(request, 'income/add_income.html', context)

        description = request.POST['description']
        date = request.POST['income_date']
        sources = request.POST['source']
        if not description:
            messages.error(request, 'Description required')
            return render(request, 'income/add_income.html', context)
        UserIncome.objects.create(owner=request.user, amount=amount, date=date, source=sources, description=description)
        messages.success(request, 'Record saved successfully')
        return redirect('income')

@login_required(login_url='login')
def edit_income(request, id):
    income = UserIncome.objects.get(pk = id)
    sources = Source.objects.all()
    context = {
        'income': income,
        'sources': sources,
        'values': income,
    }
    if request.method == "GET":
        return render(request, 'income/edit_income.html', context)
    
    if request.method == "POST":
        amount = request.POST['amount']
        description = request.POST['description']
        date = request.POST['date']
        source = request.POST['source']

        if not amount:
            messages.error(request, "Amount required")
            return render(request, 'income/edit_income.html',context)
        elif not description:
            messages.error(request, "Description of income required")
            return render(request, 'income/edit_income.html',context)
        elif not source:
            messages.error(request, "Source of Income required")
            return render(request, 'income/edit_income.html',context)
        else:
            income.owner=request.user
            income.amount=amount
            income.description=description
            income.date=date
            income.source=source
            income.save()
            messages.success(request, "Income update was a success")
            return redirect('income')
    return render(request, 'income/edit_income.html', context)

def income_delete(request, id):
    income = UserIncome.objects.get(pk = id)
    income.delete()
    messages.success(request, "Income removed")
    return redirect('income')


def generate_report(request):
    # Fetch actual data from models
    expenses = Expense.objects.all()
    income = UserIncome.objects.all()

    # Prepare data for the tables
    expenses_data = [['Date', 'Category', 'Amount']]
    for expense in expenses:
        expenses_data.append([expense.date, expense.category, expense.amount])

    income_data = [['Date', 'Source', 'Amount']]
    for item in income:
        income_data.append([item.date, item.source, item.amount])

    # Create PDF document
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="report.pdf"'

    doc = SimpleDocTemplate(response, pagesize=letter)
    elements = []

    # Add expenses table
    expenses_table = Table(expenses_data)
    expenses_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), (0.8, 0.8, 0.8)),
                                        ('TEXTCOLOR', (0, 0), (-1, 0), (1, 1, 1)),
                                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                                        ('BACKGROUND', (0, 1), (-1, -1), (0.9, 0.9, 0.9)),
                                        ]))
    elements.append(expenses_table)
    elements.append(Spacer(1, 12))  # Add space between tables

    # Add income table
    income_table = Table(income_data)
    income_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), (0.8, 0.8, 0.8)),
                                    ('TEXTCOLOR', (0, 0), (-1, 0), (1, 1, 1)),
                                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                                    ('BACKGROUND', (0, 1), (-1, -1), (0.9, 0.9, 0.9)),
                                    ]))
    elements.append(income_table)

    # Build PDF document
    doc.build(elements)
    return response
