#! /usr/bin/env python
'''
DNS Checker

Checks DNS entries for hosts.  Generates alerts when changes are detected.
'''
import hashlib
import re
import datetime
import click
import dns.resolver
from pony import orm
from SPF2IP import SPF2IP


DB = orm.Database()
CHECK_CHOICES = ('enabled', 'alert_on_change', 'check_a', 'check_mx', 'check_spf',
                 'check_cname', 'check_ns', 'check_soa', 'check_icmp', 'check_http', 'check_https')
IP_CHECK = re.compile(r'[0-9\./]+')
SPF_CHECK = 'v=spf1'
DNS_CHECKS = {
    'check_a': 'A',
    'check_cname': 'CNAME',
    'check_spf': 'TXT',
    'check_soa': 'SOA',
    'check_ns': 'NS'
}


class Check(DB.Entity):
    '''Check

    Check class.  Defines a check to run.
    '''
    obj_id = orm.PrimaryKey(int, auto=True)
    host = orm.Required(str, unique=True)
    enabled = orm.Required(bool, default=True)
    alert_on_change = orm.Required(bool, default=False)
    check_a = orm.Required(bool, default=True)
    check_mx = orm.Required(bool, default=True)
    check_spf = orm.Required(bool, default=True)
    check_cname = orm.Required(bool, default=True)
    check_ns = orm.Required(bool, default=True)
    check_soa = orm.Required(bool, default=True)
    check_icmp = orm.Required(bool, default=True)
    check_http = orm.Required(bool, default=True)
    check_https = orm.Required(bool, default=True)

    created = orm.Optional(datetime.datetime)
    modified = orm.Required(datetime.datetime)
    results = orm.Set('Result')


class Result(DB.Entity):
    '''
    Result

    Result class.  Records result of each check.
    '''
    obj_id = orm.PrimaryKey(int, auto=True)
    check = orm.Required(Check)
    check_type = orm.Required(str)
    value = orm.Optional(str)
    ips = orm.Optional(str)
    hash = orm.Optional(str, 40)
    created = orm.Required(datetime.datetime)
    alerts = orm.Set('Alert')


class Alert(DB.Entity):
    '''
    Alert

    Alert class.  Genreated when a change is detected.
    '''
    obj_id = orm.PrimaryKey(int, auto=True)
    result = orm.Required(Result)
    acknowledged = orm.Required(bool, default=False)
    value = orm.Required(str)
    created = orm.Optional(datetime.datetime)


DB.bind('sqlite', 'database.sqlite', create_db=True)
DB.generate_mapping(create_tables=True)


@click.group()
def cli():
    pass


@cli.command()
@click.argument('host')
@orm.db_session
def add_check(host):
    '''Create new check.'''
    try:
        time_hack = datetime.datetime.utcnow()
        Check(host=host, created=time_hack, modified=time_hack)
        orm.commit()
    except orm.core.TransactionIntegrityError:
        click.echo(host + ' already exists')


@cli.command()
@orm.db_session
def show_checks():
    '''Show all checks'''
    click.echo('id\thost')
    for check in orm.select(c for c in Check):
        click.echo(
            str(check.obj_id) + '\t' + check.host
        )


@cli.command()
@click.argument('check_id', type=click.INT)
@orm.db_session
def show_check(check_id):
    '''Show attributes of check from ID'''
    try:
        check = Check[check_id]
        for option in CHECK_CHOICES:
            click.echo('{0}: {1}'.format(option, str(getattr(check, option))))

        click.echo('Results:')
        for result in check.results:
            click.echo(
                '{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}'.format(
                    result.obj_id,
                    result.check.host,
                    result.check_type,
                    result.hash,
                    result.created,
                    result.value,
                    result.ips
                )
            )

    except orm.core.ObjectNotFound:
        click.echo('No check with that ID')


@cli.command()
@click.argument('check_id', type=click.INT)
@click.argument('attr', type=click.Choice(CHECK_CHOICES))
@click.argument('value', type=click.BOOL)
@orm.db_session
def edit_check(check_id, attr, value):
    '''Edit check from ID'''
    try:
        Check[check_id].set(**{attr: value, 'modified':datetime.datetime.utcnow()})
        orm.commit()
    except orm.core.ObjectNotFound:
        click.echo('No check with that ID')


@cli.command()
@click.argument('check_id', type=click.INT)
@orm.db_session
def delete_check(check_id):
    '''Delete check from ID'''
    try:
        Check[check_id].delete()
        orm.commit()
    except orm.core.ObjectNotFound:
        click.echo('No check with that ID')


@cli.command()
@click.argument('check_id', type=click.INT)
@orm.db_session
def clear_check_results(check_id):
    '''Clear results from check identified by check_id'''
    try:
        Check[check_id]
        orm.delete(result for result in Result if result.check.obj_id == check_id)
    except orm.core.ObjectNotFound:
        click.echo('No check with that ID')


@cli.command()
@orm.db_session
def do_checks():
    '''Do Check

    Preforms checks depending on check type.  Calls specific function based on check type.
    '''
    for check in orm.select(check for check in Check if check.enabled):

        for check_choice in CHECK_CHOICES:

            if check_choice in DNS_CHECKS and getattr(check, check_choice, False):

                result = Result(
                    check=check,
                    created=datetime.datetime.utcnow(),
                    check_type=check_choice
                )
                check_hash = hashlib.sha1()

                try:
                    query = dns.resolver.query(check.host, DNS_CHECKS[check_choice])

                    try:
                        check_func = globals()[check_choice]
                        values, ips = check_func(check.host, query, list(), list())
                        result.values = ','.join(values)
                        result.ips = ','.join(ips)
                        check_hash.update(bytes(result.value + result.ips, encoding='utf-8'))
                    except KeyError:
                        pass

                except dns.exception.DNSException as dns_error:
                    result.value = dns_error.msg
                    check_hash.update(bytes(result.value, encoding='utf-8'))
                    
                result.hash = check_hash.hexdigest()
                orm.commit()


def check_a(host, query, values, ips):
    for answer in query:
        values.append(answer.address)

    values.sort()
    return values, values


def check_mx(host, query, values, ips):
    hosts = list()

    for answer in query:
        value = answer.to_text()
        values.append(value)

        parts = value.split(' ')
        if IP_CHECK.match(parts[1]) is None:
            hosts.append(parts[1])
        else:
            ips.append(parts[1])

        values.sort()
    try:
        while hosts:
            host = hosts.pop()
            query = dns.resolver.query(host, 'A')

            for answer in query:
                ips.append(answer.address)

        ips.sort()

    except dns.exception.DNSException as dns_error:
        ips.append(dns_error.msg)

    return values, ips


def check_spf(host, query, values, ips):
    for answer in query:
        value = answer.to_text()
        if SPF_CHECK in value:
            values.append(value)

    values.sort()

    lookup = SPF2IP(host)
    ips = lookup.IPArray()
    ips.sort()

    return values, ips


def check_cname(host, query, values, ips):
    return simple_check(query, values, ips)


def check_soa(host, query, values, ips):
    return simple_check(query, values, ips)


def check_ns(host, query, values, ips):
    hosts = list()

    for answer in query:
        value = answer.target.to_text()
        values.append(value)

        if IP_CHECK.match(value) is None:
            hosts.append(value)
        else:
            ips.append(value)

        values.sort()
    try:
        while hosts:
            host = hosts.pop()
            query = dns.resolver.query(host, 'A')

            for answer in query:
                ips.append(answer.address)

        ips.sort()

    except dns.exception.DNSException as dns_error:
        ips.append(dns_error.msg)

    return values, ips


def simple_check(query, values, ips):
    for answer in query:
        values.append(answer.to_text())

    values.sort()
    return values, ips

if __name__ == '__main__':
    cli()
