# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2020-02-20 10:22
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('skyrock', '0019_booking_duration'),
    ]

    operations = [
        migrations.CreateModel(
            name='StudentNote',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('updated', models.DateTimeField(auto_now=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('identifier', models.UUIDField(db_index=True, default=uuid.uuid4, unique=True)),
                ('note', models.CharField(max_length=2000)),
                ('student', models.ForeignKey(blank=True, default=None, null=True, on_delete=django.db.models.deletion.CASCADE, to='skyrock.Student')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.RemoveField(
            model_name='clientnote',
            name='assignee',
        ),
        migrations.RemoveField(
            model_name='clientnote',
            name='resolved',
        ),
        migrations.AlterField(
            model_name='clientnote',
            name='client',
            field=models.ForeignKey(blank=True, default=None, null=True, on_delete=django.db.models.deletion.CASCADE, to='skyrock.Client'),
        ),
        migrations.AlterField(
            model_name='clientnote',
            name='user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
