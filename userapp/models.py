from django.db import models

# Create your models here.


class Verify(models.Model):
    id = models.ForeignKey('core.User', on_delete=models.CASCADE, db_column='id')
    start=models.CharField(max_length=200)
    sr = models.AutoField(primary_key=True)

    class Meta:
        db_table='verify'