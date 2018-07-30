from django.conf.urls import url
from trust_monitor import views

urlpatterns = [
    url(r'^register_node/$', views.RegisterNode.as_view()),
    url(r'^attest_node/$', views.AttestNode.as_view()),
    url(r'^status/$', views.Status.as_view()),
    url(r'^verify_callback/$', views.VerifyCallback.as_view()),
    url(r'^known_digests/$', views.Known_Digest.as_view()),
    url(r'^nfvi_attestation_info/$', views.AttestNFVI.as_view()),
    url(r'^nfvi_pop_attestation_info/$', views.AttestNFVIPoP.as_view()),
]
