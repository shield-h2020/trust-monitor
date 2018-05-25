from django.conf.urls import url
from trust_monitor import views

urlpatterns = [
    url(r'^register_node/$', views.RegisterNode.as_view()),
    url(r'^attest_node/$', views.AttestNode.as_view()),
    url(r'^get_status_info/$', views.StatusTrustMonitor.as_view()),
    url(r'^get_verify/$', views.GetVerify.as_view()),
    url(r'^known_digests/$', views.Known_Digest.as_view()),
    url(r'^get_nfvi_attestation_info/$', views.AttestAllNFVI.as_view()),
    url(r'^get_nfvi_pop_attestation_info/$', views.AttestNFVI.as_view()),
]
