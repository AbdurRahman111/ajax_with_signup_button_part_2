# Generated by Django 3.1.6 on 2021-05-01 17:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0041_auto_20210501_1455'),
    ]

    operations = [
        migrations.AddField(
            model_name='reservation',
            name='paid',
            field=models.BooleanField(null=True),
        ),
    ]
