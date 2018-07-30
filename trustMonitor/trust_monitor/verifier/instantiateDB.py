import os
from util import *
import logging
from trust_monitor.models import KnownDigest
from django.db import OperationalError
import redis

logger = logging.getLogger('verifier')


# define list of known digests at start of django
class InstantiateDigest:
    known_digests = []

    @staticmethod
    def instantiate_known_digest():
        # define list of known digest at start of django
        try:
            list_d = KnownDigest.objects.values('digest')
            for dig in list_d:
                InstantiateDigest.known_digests.append(dig.get('digest'))
                logger.info('Set a list of known_digests')
        except OperationalError as e:
            logger.error(e)

        # Instantiate digests included in Redis DB
        logger.info('instantiate known_digests with elements in Redis DB')
        list_digest = []
        try:
            redisDB = redis.Redis(host='tm_database_redis', port='6379')
            list_keys = redisDB.keys('*')
            for key in list_keys:
                logger.debug('Added value of key: %s in list' % key)
                value = redisDB.get(key)
                list_digest.append(value)
        except redis.ConnectionError as e:
            jsonError = {'Error', 'Impossible to contact to Redis DB'}
            logger.warning('Impossible included the digests in Redis DB')
            logger.warning(jsonError)
        InstantiateDigest.known_digests.extend(list_digest)


class DigestListUpdater:
    def append_known_digest(digest):
        if digest is InstantiateDigest.known_digests:
            logger.info('Digest %s already exist in the list of digest'
                        % digest)
        else:
            InstantiateDigest.known_digests.append(digest)
            logger.info('Added digest %s in the list', digest)

    def remove_known_digest(digest):
        InstantiateDigest.known_digests.remove(digest)
        logger.info('Removed digest %s in the list', digest)
