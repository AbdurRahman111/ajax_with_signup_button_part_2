# Generated by Django 3.1.6 on 2021-03-19 17:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0003_experience_title1'),
    ]

    operations = [
        migrations.AddField(
            model_name='experience',
            name='slug',
            field=models.SlugField(default='SHARE THE FUN'),
            preserve_default=False,
        ),
    ]
