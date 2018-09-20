from django.db import models
# Class to manage hosts


class Host(models.Model):
    hostName = models.TextField()
    address = models.CharField(max_length=16, blank=False)
    pcr0 = models.CharField(max_length=40, default='')
    distribution = models.TextField()
    analysisType = models.TextField(
        default='load-time+cont-check,l_req=l4_ima_all_ok|==,cont-list=')
    driver = models.TextField()

    class Meta:
        ordering = ('id',)


class KnownDigest(models.Model):
    pathFile = models.TextField()
    digest = models.CharField(max_length=40, blank=False)

    class Meta:
        ordering = ('id',)
