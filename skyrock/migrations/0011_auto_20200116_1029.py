# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2020-01-16 10:29
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('skyrock', '0010_auto_20200116_1006'),
    ]

    operations = [
        migrations.AlterField(
            model_name='session',
            name='club',
            field=models.CharField(blank=True, db_index=True, max_length=50),
        ),
    ]
