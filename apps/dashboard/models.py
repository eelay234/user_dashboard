from __future__ import unicode_literals
from django.db import models
import re
from django.http import HttpResponse
from django.contrib import messages

# Create your models here.
class User(models.Model):
    first_name = models.CharField(max_length=45)
    last_name = models.CharField(max_length=45)
    email = models.EmailField(max_length=75)
    password = models.CharField(max_length=100)
    user_level = models.IntegerField()
    description = models.TextField(max_length=1000)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)

        # Re-adds objects as a manager (so all the normal ORM literature matches)
    objects = models.Manager()

class Post(models.Model):
    message = models.TextField(max_length=1000)
    msg_user_id = models.ForeignKey(User, default="", blank=True, related_name="muser")
    #author = models.CharField(max_length=42)
    author_id = models.ForeignKey(User, default="", blank=True, related_name="author")
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)

    objects = models.Manager()

class Comment(models.Model):
    message = models.TextField(max_length=1000)
    post_id = models.ForeignKey(Post, default="", blank=True, related_name="post")
    #author = models.CharField(max_length=42)
    author_id = models.ForeignKey(User, default="", blank=True, related_name="comment_author")
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)

    objects = models.Manager()

    #def __str__(self):
    #        return '{} wrote {} {}'.format(self.author.first_name+" "+self.author.last_name, self.created_at, self.message)
