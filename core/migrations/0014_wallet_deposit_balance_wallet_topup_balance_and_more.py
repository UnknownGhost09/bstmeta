# Generated by Django 4.1.4 on 2023-09-07 05:54

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0013_userwithdrawls_bonus_amount_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="wallet",
            name="deposit_balance",
            field=models.CharField(default="0", max_length=250),
        ),
        migrations.AddField(
            model_name="wallet",
            name="topup_balance",
            field=models.CharField(default="0", max_length=250),
        ),
        migrations.AlterField(
            model_name="businesslogs",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 5, 54, 47, 687979), max_length=100
            ),
        ),
        migrations.AlterField(
            model_name="changesponserlogs",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 5, 54, 47, 688979), max_length=100
            ),
        ),
        migrations.AlterField(
            model_name="farmingroilogs",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 5, 54, 47, 689979), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="levelincome",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 5, 54, 47, 691980), max_length=100
            ),
        ),
        migrations.AlterField(
            model_name="newsmodel",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 5, 54, 47, 690980), max_length=100
            ),
        ),
        migrations.AlterField(
            model_name="ptransfer",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 5, 54, 47, 693980), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="stakingroilogs",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 5, 54, 47, 690980), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="status_activity",
            name="time",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 5, 54, 47, 692980), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="ticketmodel",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 5, 54, 47, 692980), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="created_at",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 5, 54, 47, 686979), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="updated_at",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 5, 54, 47, 686979), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="usercofounderclub",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 5, 54, 47, 694979), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="usermembership",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 5, 54, 47, 689979), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="userrank",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 5, 54, 47, 694979), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="userreferral",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 5, 54, 47, 693980), max_length=100
            ),
        ),
        migrations.AlterField(
            model_name="userstaking",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 5, 54, 47, 689979), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="userwithdrawls",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 5, 54, 47, 692980), max_length=200
            ),
        ),
    ]
