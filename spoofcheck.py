#! /usr/bin/env python

import sys

from colorama import init as color_init

import emailprotectionslib.dmarc as dmarclib
import emailprotectionslib.spf as spflib

from libs.PrettyOutput import output_good, output_bad, \
    output_info, output_error, output_indifferent


def check_spf_all_string(spf_record):
    strong_spf_all_string = False
    if spf_record.all_string is not None:
        if spf_record.all_string == "~all" or spf_record.all_string == "-all":
            output_indifferent("SPF record contains an All item: " + spf_record.all_string)
        else:
            output_good("SPF record All item is too weak: " + spf_record.all_string)
            strong_spf_all_string = True
    else:
        output_good("SPF record has no All string")

    return strong_spf_all_string


def is_spf_record_strong(domain):
    strong_spf_record = True
    try:
        spf_record = spflib.SpfRecord.from_domain(domain)
        output_info("Found SPF record:")
        output_info(str(spf_record.record))

        all_string_weak = check_spf_all_string(spf_record)
        if all_string_weak is True:
            strong_spf_record = False

    except spflib.NoSpfRecordException:
        output_good(domain + " has no SPF record!")
        strong_spf_record = False

    return strong_spf_record


def get_dmarc_record(domain):
    dmarc = dmarclib.DmarcRecord.from_domain(domain)
    output_info("Found DMARC record:")
    output_info(str(dmarc.record))
    return dmarc


def check_dmarc_extras(dmarc_record):
    if dmarc_record.pct is not None and dmarc_record.pct != str(100):
            output_indifferent("DMARC pct is set to " + dmarc_record.pct + "% - might be possible")

    if dmarc_record.rua is not None:
        output_indifferent("Aggregate reports will be sent: " + dmarc_record.rua)

    if dmarc_record.ruf is not None:
        output_indifferent("Forensics reports will be sent: " + dmarc_record.ruf)


def check_dmarc_policy(dmarc_record):
    policy_strength = False
    if dmarc_record.policy is not None:
        if dmarc_record.policy == "reject" or dmarc_record.policy == "quarantine":
            policy_strength = True
            output_bad("DMARC policy set to " + dmarc_record.policy)
        else:
            output_good("DMARC policy set to " + dmarc_record.policy)
    else:
        output_good("DMARC record has no Policy")

    return policy_strength


def is_dmarc_record_strong(domain):
    dmarc_record_strong = False

    try:
        dmarc = get_dmarc_record(domain)

        dmarc_record_strong = check_dmarc_policy(dmarc)

        check_dmarc_extras(dmarc)

    except dmarclib.NoDmarcRecordException:
        output_good(domain + " has no DMARC record!")

    return dmarc_record_strong

if __name__ == "__main__":
    color_init()
    spoofable = False

    try:
        domain = sys.argv[1]

        spf_record_strength = is_spf_record_strong(domain)
        if spf_record_strength is False:
            spoofable = True

        dmarc_record_strength = is_dmarc_record_strong(domain)
        if dmarc_record_strength is False:
            spoofable = True

        if spoofable:
            output_good("Spoofing possible for " + domain + "!")
        else:
            output_bad("Spoofing not possible for " + domain)

    except IndexError:
        output_error("Usage: " + sys.argv[0] + " [DOMAIN]")