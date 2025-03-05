from django.db import models

# Create your models here.
from django.db.models import CASCADE


class ClientRegister_Model(models.Model):
    username = models.CharField(max_length=30)
    email = models.EmailField(max_length=30)
    password = models.CharField(max_length=10)
    phoneno = models.CharField(max_length=10)
    country = models.CharField(max_length=30)
    state = models.CharField(max_length=30)
    city = models.CharField(max_length=30)
    address = models.CharField(max_length=300)
    gender = models.CharField(max_length=30)

class detection_of_ongoing_cyber_attacks(models.Model):

    cve_id=models.CharField(max_length=300)
    vendor_project=models.CharField(max_length=300)
    product=models.CharField(max_length=300)
    threat_name=models.CharField(max_length=300)
    date_added=models.CharField(max_length=300)
    short_description=models.CharField(max_length=300)
    required_action=models.CharField(max_length=300)
    due_date=models.CharField(max_length=300)
    pub_date=models.CharField(max_length=300)
    cvss=models.CharField(max_length=300)
    cwe=models.CharField(max_length=300)
    Type=models.CharField(max_length=300)
    complexity=models.CharField(max_length=300)
    Prediction=models.CharField(max_length=300)


class cyber_threat_type_ratio(models.Model):

    names = models.CharField(max_length=300)
    ratio = models.CharField(max_length=300)

class detection_accuracy(models.Model):

    names = models.CharField(max_length=300)
    ratio = models.CharField(max_length=300)

class CapturedThreat(models.Model):
    cve_id = models.CharField(max_length=100)
    vendor_project = models.CharField(max_length=100)
    product = models.CharField(max_length=100)
    threat_name = models.CharField(max_length=200)
    date_added = models.CharField(max_length=100)  # Changed to CharField for flexibility
    short_description = models.TextField()
    required_action = models.TextField()
    due_date = models.CharField(max_length=100)    # Changed to CharField for flexibility
    pub_date = models.CharField(max_length=100)    # Changed to CharField for flexibility
    cvss = models.CharField(max_length=10)         # Changed to CharField for flexibility
    cwe = models.CharField(max_length=100)
    type = models.CharField(max_length=100)
    complexity = models.CharField(max_length=50)
    capture_time = models.DateTimeField(auto_now_add=True)
    analyzed = models.BooleanField(default=False)
    prediction_result = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return f"{self.cve_id} - {self.threat_name}"