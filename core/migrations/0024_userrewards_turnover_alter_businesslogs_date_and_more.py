# Generated by Django 4.1.4 on 2023-09-11 17:34

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0023_levels_reffers_alter_businesslogs_date_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="userrewards",
            name="turnover",
            field=models.CharField(default="Team", max_length=200),
        ),
        migrations.AlterField(
            model_name="businesslogs",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 11, 17, 34, 8, 67751), max_length=100
            ),
        ),
        migrations.AlterField(
            model_name="changesponserlogs",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 11, 17, 34, 8, 67751), max_length=100
            ),
        ),
        migrations.AlterField(
            model_name="farmingroilogs",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 11, 17, 34, 8, 67751), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="levelincome",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 11, 17, 34, 8, 67751), max_length=100
            ),
        ),
        migrations.AlterField(
            model_name="newsmodel",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 11, 17, 34, 8, 67751), max_length=100
            ),
        ),
        migrations.AlterField(
            model_name="ptransfer",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 11, 17, 34, 8, 67751), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="stakingroilogs",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 11, 17, 34, 8, 67751), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="status_activity",
            name="time",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 11, 17, 34, 8, 67751), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="ticketmodel",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 11, 17, 34, 8, 67751), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="created_at",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 11, 17, 34, 8, 67751), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="updated_at",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 11, 17, 34, 8, 67751), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="usercofounderclub",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 11, 17, 34, 8, 67751), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="usermembership",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 11, 17, 34, 8, 67751), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="userrank",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 11, 17, 34, 8, 67751), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="userreferral",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 11, 17, 34, 8, 67751), max_length=100
            ),
        ),
        migrations.AlterField(
            model_name="userrewards",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 11, 23, 4, 8, 67751), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="userstaking",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 11, 17, 34, 8, 67751), max_length=200
            ),
        ),
        migrations.AlterField(
            model_name="userwithdrawls",
            name="date",
            field=models.CharField(
                default=datetime.datetime(2023, 9, 11, 17, 34, 8, 67751), max_length=200
            ),
        ),
    ]