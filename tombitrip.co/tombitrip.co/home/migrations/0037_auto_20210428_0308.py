# Generated by Django 3.1.6 on 2021-04-27 21:08

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0036_auto_20210428_0136'),
    ]

    operations = [
        migrations.AlterField(
            model_name='productattribute',
            name='transmission',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='home.transmission'),
        ),
    ]