# Generated by Django 3.1.6 on 2021-05-05 19:48

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0043_auto_20210505_1803'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='supply',
            name='drop_of_before',
        ),
        migrations.RemoveField(
            model_name='supply',
            name='pick_up_from',
        ),
    ]
