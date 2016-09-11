# -*- coding: utf-8 -*-
# Generated by Django 1.10 on 2016-09-11 01:50
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0002_auto_20160825_1548'),
    ]

    operations = [
        migrations.CreateModel(
            name='Comment',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('message', models.TextField(max_length=1000)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('author_id', models.ForeignKey(blank=True, default='', on_delete=django.db.models.deletion.CASCADE, related_name='comment_author', to='dashboard.User')),
                ('post_id', models.ForeignKey(blank=True, default='', on_delete=django.db.models.deletion.CASCADE, related_name='post', to='dashboard.Post')),
            ],
        ),
    ]