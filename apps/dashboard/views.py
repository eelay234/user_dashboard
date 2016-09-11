from django.shortcuts import render, redirect, HttpResponse
from django.contrib import messages
import bcrypt
import re
from django.contrib.auth import authenticate
from .models import User, Post, Comment
from datetime import datetime

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
#Our new manager!
def check_password(request, email, password):
      u = User.objects.filter(email=email).first()
      if u == None:
          messages.add_message(request, messages.ERROR, "Not registered, please register!")
          return 1
      hashed = u.password
      if bcrypt.hashpw(password.encode("utf-8"), hashed.encode("utf-8")) == hashed.encode("utf-8"):
        print "It matches"
        return u
      else:
        messages.add_message(request, messages.ERROR, "Password not matched!")
        print "It does not match"
        return 2

def index(request):
  return render(request, "dashboard/index.html")

def signin(request):
  return render(request, "dashboard/signin.html")

def register(request):
  return render(request, "dashboard/register.html")

def login(request):
    error = None
    email = request.POST['email']
    password = request.POST['password']
    if len(email) < 1:
       error="error"
       messages.add_message(request, messages.ERROR, 'email can not be blank! ')
    else:
       if not EMAIL_REGEX.match(email):
         error="error"
         messages.add_message(request, messages.ERROR, 'Invalid Email Address! ')
    if len(password) < 8:
        messages.add_message(request, messages.ERROR, 'Password has to be at least 8 characters! ')
        error="error"
    if error == "error":
        return redirect("/signin")
        #return render(request, 'dashboard/signin.html')
    user = check_password(request=request, email=email, password=password)
    if user == 1:
        return redirect("/register")
    if user == 2:
        return redirect("/signin")
    if user != None:
        request.session['user_id'] = user.id
        request.session['user_level'] = user.user_level
        return redirect("/show_dashboard")
        # context = {
        #   "users": User.objects.all()
        # }
        # return render(request, 'dashboard/dashboard.html', context)
def show_dashboard(request):
    context = {
      "users": User.objects.all()
    }
    return render(request, 'dashboard/dashboard.html', context)

def registration(request):
        error = None
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        password = request.POST['password']
        if len(email) < 1:
           error="error"
           messages.add_message(request, messages.ERROR, 'email can not be blank! ')
        else:
           if not EMAIL_REGEX.match(email):
             error="error"
             messages.add_message(request, messages.ERROR, 'Invalid Email Address! ')
        if len(password) < 8:
           messages.add_message(request, messages.ERROR, 'Password has to be at least 8 characters! ')
           error="error"
        confirm_password = request.POST['password_confirm']
        if password != confirm_password:
           error="error"
           messages.add_message(request, messages.ERROR, 'Password and Confirm Password do not match! ')
        if len(request.POST['first_name']) < 2:
           error="error"
           messages.add_message(request, messages.ERROR, 'First name has to be at least 2 letters! ')
        else:
           if str.isalpha(str(request.POST['first_name'])) == False:
             error="error"
             messages.add_message(request, messages.ERROR, 'First name has to only contain letters! ')
        if len(request.POST['last_name']) < 2:
            error="error"
            messages.add_message(request, messages.ERROR, 'Last name has to be at least 2 letters! ')
        else:
           if str.isalpha(str(request.POST['last_name'])) == False:
             error="error"
             messages.add_message(request, messages.ERROR, 'Last name has to only contain letters! ')
        if error == None:
            if User.objects.filter(email=email).first():
                messages.add_message(request, messages.ERROR, 'user exists! Please log in! ')
                return redirect("/register")
            # if len(User.objects.all()) == 0:
            if User.objects.all().count == 0:
                user_level = 9
            else:
                user_level = 1
            passwd_encoded = password.encode('utf-8')
            hashed = bcrypt.hashpw(passwd_encoded, bcrypt.gensalt())
            user = User.objects.create(first_name=first_name, last_name=last_name, password=hashed, email=email,  user_level=user_level)
            request.session['user_id'] = user.id
            request.session['user_level'] = user.user_level
            return redirect("/show_dashboard")
        else:
            return redirect("/register")
def edit(request):
  context = {
    "user": User.objects.get(id=request.session['user_id'])
  }
  return render(request, "dashboard/edit.html", context)

def update_info(request, id):
  u = User.objects.get(id=id)
  u.email = request.POST['email']
  u.first_name = request.POST['first_name']
  u.last_name = request.POST['last_name']
  u.save()
  print "edit:"
  print User.objects.get(id=id).last_name
  context = {
    "users": User.objects.all()#User.objects.get(id=user.id)
  }
  return render(request, "dashboard/dashboard.html", context)

def update_password(request, id):
  u = User.objects.get(id=id)
  password = request.POST['password']
  confirm_password = request.POST['password_confirm']
  error = None
  if len(password) < 8:
     messages.add_message(request, messages.ERROR, 'Password has to be at least 8 characters! ')
     error="error"
  if password != confirm_password:
     error="error"
     messages.add_message(request, messages.ERROR, 'Password and Confirm Password do not match! ')
  if error == None:
      u.password = password
      u.save()
      print "after update password:"
      print User.objects.get(id=id).password
      context = {
        "users": User.objects.all()#User.objects.get(id=user.id)
      }
      return render(request, "dashboard/dashboard.html", context)
  else:
      context = {
        "user": u
      }
      return render(request, "dashboard/edit.html", context)
      #return redirect('users/edit/'+id, context=context)

def update_description(request, id):
  u = User.objects.get(id=id)
  u.description = request.POST['description']
  u.save()
  print "after update description:"
  print User.objects.get(id=id).description
  context = {
    "users": User.objects.all()#User.objects.get(id=user.id)
  }
  return render(request, "dashboard/dashboard.html", context)

def show(request, id):
  #def v1 ( request, a, b ):
    # for URL 'v1/17/18', a == '17' and b == '18'.
  #    pass
  u = User.objects.get(id=id)
  posts = Post.objects.filter(msg_user_id=u)
  print "shown:"

  for p in posts:
      p.cset = Comment.objects.filter(post_id = p)
    #   p.created_date = p.created_at
  context = {
    "posts" : posts,
    "msg_user": u,
    "users": User.objects.all()#User.objects.get(id=user.id)
  }
  return render(request, "dashboard/show.html", context)

def post_comment(request, id, m_id):
    u = User.objects.get(id=request.session['user_id'])
    p = Post.objects.get(id=id)
    Comment.objects.create(message=request.POST['message'], post_id=p, author_id=u)
    return redirect("/users/show/"+m_id)

def post(request, id):
   #def v1 ( request, a, b ):
     # for URL 'v1/17/18', a == '17' and b == '18'.
   #    pass
   u = User.objects.get(id=id)
   login_u = User.objects.get(id=request.session['user_id'])
   print "login_u"
   print login_u.first_name
   print "post%%%%%%%%%%%:"
   # pp = Post.objects.filter(msg_user_id=u).first()
   # print pp
   # pp.message=request.POST['message']
   # pp.author=login_u
   # pp.save()
   post=Post.objects.create(message=request.POST['message'], msg_user_id=u, author_id=login_u)

   return redirect("/users/show/"+id)
   # posts = Post.objects.filter(msg_user_id=u)
   # context = {
   #   "posts" : posts,
   #   "login_user": login_u,
   #   "msg_user": u,
   #   "users": User.objects.all()#User.objects.get(id=user.id)
   # }
   # print "post author:"
   # print posts
   # print pp.message
   # return render(request, "dashboard/show.html", context)

def new(request):
    return render(request, "dashboard/new.html")


def admin_update_info(request, id):
  u = User.objects.get(id=id)
  u.email = request.POST['email']
  u.first_name = request.POST['first_name']
  u.last_name = request.POST['last_name']
  if request.POST['user_level'] == "normal":
      u.user_level = 1
  else:
      u.user_level = 9
  print "usr level"
  print request.POST['user_level']
  u.save()
  print u.user_level
  print "edit:"
  print User.objects.get(id=id).last_name
  context = {
    "users": User.objects.all()#User.objects.get(id=user.id)
  }
  return render(request, "dashboard/dashboard.html", context)

def admin_update_password(request, id):
  u = User.objects.get(id=id)
  password = request.POST['password']
  confirm_password = request.POST['password_confirm']
  error = None
  if len(password) < 8:
     messages.add_message(request, messages.ERROR, 'Password has to be at least 8 characters! ')
     error="error"
  if password != confirm_password:
     error="error"
     messages.add_message(request, messages.ERROR, 'Password and Confirm Password do not match! ')
  if error == None:
      passwd_encoded = password.encode('utf-8')
      hashed = bcrypt.hashpw(passwd_encoded, bcrypt.gensalt())
      u.password = hashed
      u.save()
      print "after update password:"
      print User.objects.get(id=id).password
      context = {
        "users": User.objects.all()#User.objects.get(id=user.id)
      }
      return render(request, "dashboard/dashboard.html", context)
  else:
      u = User.objects.get(id=id)
      context = {
        "user": User.objects.get(id=id)
      }
      return render(request, "dashboard/edit.html", context)
      #return redirect('users/edit/'+id, context=context)

def admin_edit(request, id):
  context={
    "user": User.objects.get(id=id),
  }
  print "admin edit:"
  print User.objects.get(id=id).email
  return render(request, "dashboard/admin_edit.html", context)

def remove(request, id):
  u = User.objects.get(id=id)
  pp = Post.objects.filter(msg_user_id=u)
  u.delete()
  for p in pp:
      p.delete()
  context={
    "users": User.objects.all(),
  }
  return render(request, "dashboard/dashboard.html", context)

def logoff(request):
    del request.session['user_level']
    del request.session['user_id']
    return redirect('/')
