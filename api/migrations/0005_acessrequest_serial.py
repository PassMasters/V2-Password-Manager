# Generated by Django 4.2.7 on 2024-01-19 17:15

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0004_acessrequest_aproval_alter_linkeduser_premisions"),
    ]

    operations = [
        migrations.AddField(
            model_name="acessrequest",
            name="Serial",
            field=models.CharField(default="0000", max_length=255),
        ),
    ]