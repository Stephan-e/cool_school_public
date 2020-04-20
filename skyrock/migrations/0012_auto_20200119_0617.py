# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2020-01-19 06:17
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('skyrock', '0011_auto_20200116_1029'),
    ]

    operations = [
        migrations.CreateModel(
            name='Staff',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('updated', models.DateTimeField(auto_now=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('identifier', models.UUIDField(db_index=True, default=uuid.uuid4, unique=True)),
                ('first_name', models.CharField(blank=True, db_index=True, max_length=50)),
                ('last_name', models.CharField(blank=True, db_index=True, max_length=50)),
                ('birth_date', models.DateField(blank=True, null=True)),
                ('language', models.CharField(blank=True, db_index=True, max_length=200)),
                ('email', models.EmailField(max_length=254, null=True, verbose_name='email address')),
                ('phone', models.CharField(blank=True, db_index=True, max_length=50)),
                ('location', models.CharField(blank=True, db_index=True, max_length=50)),
                ('role', models.CharField(blank=True, db_index=True, max_length=50)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.AddField(
            model_name='trial',
            name='sales_representative',
            field=models.ForeignKey(blank=True, default=None, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='trial', to='skyrock.Staff'),
        ),
        migrations.AddField(
            model_name='user',
            name='staff',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='user', to='skyrock.Staff'),
        ),
    ]
