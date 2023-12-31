# Generated by Django 4.1.4 on 2023-09-07 10:15

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0015_userwithdrawls_deposit_amount_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="businesslogs",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 10, 15, 54, 111502),
                max_length=100,
            ),
        ),
        migrations.AlterField(
            model_name="changesponserlogs",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 10, 15, 54, 112481),
                max_length=100,
            ),
        ),
        migrations.AlterField(
            model_name="farmingroilogs",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 10, 15, 54, 113487),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="levelincome",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 10, 15, 54, 115481),
                max_length=100,
            ),
        ),
        migrations.AlterField(
            model_name="newsmodel",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 10, 15, 54, 114492),
                max_length=100,
            ),
        ),
        migrations.AlterField(
            model_name="ptransfer",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 10, 15, 54, 116400),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="stakingroilogs",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 10, 15, 54, 113487),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="status_activity",
            name="time",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 10, 15, 54, 116400),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="ticketmodel",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 10, 15, 54, 115481),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="created_at",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 10, 15, 54, 110485),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="updated_at",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 10, 15, 54, 110485),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="usercofounderclub",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 10, 15, 54, 117482),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="usermembership",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 10, 15, 54, 113487),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="userrank",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 10, 15, 54, 118483),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="userreferral",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 10, 15, 54, 117482),
                max_length=100,
            ),
        ),
        migrations.AlterField(
            model_name="userstaking",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 10, 15, 54, 113487),
                max_length=200,
            ),
        ),
        migrations.AlterField(
            model_name="userwithdrawls",
            name="bonus_amount",
            field=models.CharField(default="0", max_length=250),
        ),
        migrations.AlterField(
            model_name="userwithdrawls",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 7, 10, 15, 54, 116400),
                max_length=200,
            ),
        ),
    ]
