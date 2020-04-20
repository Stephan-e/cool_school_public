# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2020-03-29 08:20
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('skyrock', '0038_auto_20200309_1457'),
    ]

    operations = [
        migrations.AddField(
            model_name='campbooking',
            name='lunch',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='campbooking',
            name='note',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='campsession',
            name='week',
            field=models.ForeignKey(blank=True, default=None, null=True, on_delete=django.db.models.deletion.CASCADE, to='skyrock.CampWeek'),
        ),
    ]
