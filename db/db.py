import os

from ..logs.logger import log

import psycopg2

class DB():
    __connection = None

    def __init__(self, host, port, user, password, database) -> None:

        while (1):
            try:
                self.__connection = psycopg2.connect(dbname=database, user=user, password=password, host=host, port=port)
                break
            except:
                log("Trying to connect to sql server...")
                
        log("Initiated DB connection!")

    def querySamples(self, sql):
        result = []
        cursor = self.__connection.cursor()

        cursor.execute(sql)
        try:
            for sample in cursor.fetchall():
                result.append(sample[1])
            return result
        except:
            return []

    def sampleExists(self, sample: object):
        cursor = self.__connection.cursor()

        cursor.execute("SELECT id FROM sample WHERE sha256_hash=%s", (sample["sha256_hash"][:64],))
        try:
            cursor.fetchall()[0][0]
            return True
        except:
            return False
    
    def addSample(self, sample: object) -> None:
        address_ids = []
        domain_ids = []

        cursor = self.__connection.cursor()

        for address in sample["related_ips"]:
            if(len(address) > 16): continue
            try:
                cursor.execute("INSERT INTO ip_address(ip_address) VALUES(%s) RETURNING id", (address,))
            except(psycopg2.errors.UniqueViolation):
                self.__connection.commit()
                cursor.execute("SELECT id FROM ip_address WHERE ip_address=%s", (address,))

            self.__connection.commit()
            
            try:
                address_ids.append(cursor.fetchall()[0][0])
            except(psycopg2.ProgrammingError):
                pass

        for domain in sample["related_domains"]:
            if(len(domain) > 32): continue
            try:
                cursor.execute("INSERT INTO domain(domain) VALUES(%s) RETURNING id", (domain,))
            except(psycopg2.errors.UniqueViolation):
                self.__connection.commit()
                cursor.execute("SELECT id FROM domain WHERE domain=%s", (domain,))

            self.__connection.commit()
            
            try:
                domain_ids.append(cursor.fetchall()[0][0])
            except(psycopg2.ProgrammingError):
                pass
        
        sample_id = None

        try:
            cursor.execute("""
                           INSERT INTO sample(sha256_hash, md5_hash, malware_family, mime, first_seen, last_seen, file_name, file_size, tags)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                           RETURNING id
                           """, (sample["sha256_hash"][:64], sample["md5_hash"][:32] if sample["md5_hash"] else None, sample["malware_family"][:32] if sample["malware_family"] else None,
                            sample["mime"][:32] if sample["mime"] else None, sample["first_seen"], sample["last_seen"], sample["file_name"][:64],
                            sample["file_size"], [tag[:16] for tag in sample["tags"]]))
            self.__connection.commit()

            try:
                sample_id = cursor.fetchall()[0][0]
            except(psycopg2.ProgrammingError):
                pass

        except(psycopg2.errors.UniqueViolation):
            self.__connection.commit()
            cursor.execute("SELECT id FROM sample WHERE sha256_hash=%s", (sample["sha256_hash"][:64],))
            try:
                sample_id = cursor.fetchall()[0][0]
            except(psycopg2.ProgrammingError):
                pass
            pass
            
        for id in address_ids:
            try:
                cursor.execute("INSERT INTO sample_ip_address_relation(sample_id, ip_address_id) VALUES (%s, %s)", (sample_id, id,))
                self.__connection.commit()
            except(psycopg2.errors.UniqueViolation):
                pass
            self.__connection.commit()

        for id in domain_ids:
            try:
                cursor.execute("INSERT INTO sample_domain_relation(sample_id, domain_id) VALUES (%s, %s)", (sample_id, id,))
                self.__connection.commit()
            except(psycopg2.errors.UniqueViolation):
                pass
            self.__connection.commit()