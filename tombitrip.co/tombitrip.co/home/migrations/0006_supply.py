# Generated by Django 3.1.6 on 2021-03-20 15:38

import ckeditor_uploader.fields
import datetime
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('home', '0005_auto_20210320_0005'),
    ]

    operations = [
        migrations.CreateModel(
            name='Supply',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=150)),
                ('car_title', models.CharField(max_length=150)),
                ('city', models.CharField(max_length=150)),
                ('price', models.IntegerField()),
                ('main_photo', models.ImageField(upload_to='photos/%Y/%m/%d/')),
                ('image1', models.ImageField(blank=True, upload_to='photos/%Y/%m/%d/')),
                ('image2', models.ImageField(blank=True, upload_to='photos/%Y/%m/%d/')),
                ('image3', models.ImageField(blank=True, upload_to='photos/%Y/%m/%d/')),
                ('image4', models.ImageField(blank=True, upload_to='photos/%Y/%m/%d/')),
                ('image5', models.ImageField(blank=True, upload_to='photos/%Y/%m/%d/')),
                ('image6', models.ImageField(blank=True, upload_to='photos/%Y/%m/%d/')),
                ('image7', models.ImageField(blank=True, upload_to='photos/%Y/%m/%d/')),
                ('image8', models.ImageField(blank=True, upload_to='photos/%Y/%m/%d/')),
                ('image9', models.ImageField(blank=True, upload_to='photos/%Y/%m/%d/')),
                ('image10', models.ImageField(blank=True, upload_to='photos/%Y/%m/%d/')),
                ('image11', models.ImageField(blank=True, upload_to='photos/%Y/%m/%d/')),
                ('image12', models.ImageField(blank=True, upload_to='photos/%Y/%m/%d/')),
                ('image13', models.ImageField(blank=True, upload_to='photos/%Y/%m/%d/')),
                ('image14', models.ImageField(blank=True, upload_to='photos/%Y/%m/%d/')),
                ('image15', models.ImageField(blank=True, upload_to='photos/%Y/%m/%d/')),
                ('image16', models.ImageField(blank=True, upload_to='photos/%Y/%m/%d/')),
                ('image17', models.ImageField(blank=True, upload_to='photos/%Y/%m/%d/')),
                ('seats', models.IntegerField()),
                ('bearth', models.IntegerField()),
                ('features', ckeditor_uploader.fields.RichTextUploadingField()),
                ('description', ckeditor_uploader.fields.RichTextUploadingField()),
                ('failities', ckeditor_uploader.fields.RichTextUploadingField()),
                ('houserules', ckeditor_uploader.fields.RichTextUploadingField()),
                ('min_reserver_period', models.IntegerField()),
                ('pick_up_from', models.DateTimeField(blank=True, default=datetime.datetime.now)),
                ('drop_of_before', models.DateTimeField(blank=True, default=datetime.datetime.now)),
                ('is_published', models.BooleanField(default=True)),
                ('favourite', models.ManyToManyField(blank=True, related_name='favourite', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]