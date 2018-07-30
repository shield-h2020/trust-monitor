from rest_framework import serializers
from trust_monitor.models import Host, KnownDigest

# define serializer method to host table


class HostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Host
        fields = ('id',
                  'hostName',
                  'address',
                  'pcr0',
                  'distribution',
                  'analysisType',
                  'driver')


class ResultSerializer(serializers.Serializer):
    host_id = serializers.CharField()
    trust_level = serializers.CharField()
    vtime = serializers.DateTimeField()


class DigestSerializer(serializers.ModelSerializer):
    class Meta:
        model = KnownDigest
        fields = ('id', 'pathFile', 'digest')


class DigestRemoved(serializers.Serializer):
    digest = serializers.CharField(max_length=40)


class NodeListVNFS(serializers.Serializer):
    node = serializers.CharField()
    vnfs = serializers.ListField(child=serializers.CharField(),
                                 default='', required=False)


class NodeListSerializer(serializers.Serializer):
    node_list = serializers.ListField(
        child=NodeListVNFS())


class VerificationValues(serializers.Serializer):
    distribution = serializers.CharField()
    analysis = serializers.CharField()
    report_url = serializers.CharField()
    report_id = serializers.IntegerField()


class VerificationInputNFVI(serializers.Serializer):
    node_id = serializers.CharField()


class VerificationDeleteRegisteredNode(serializers.Serializer):
    hostName = serializers.CharField()
