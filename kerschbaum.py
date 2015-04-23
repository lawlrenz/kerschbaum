# -*- coding: utf8 -*-

import math
import time
import hmac
import hashlib

""" Distance preserving pseudonymization algorithm (Florian Kerschbaum) for timevalues (easily expandable for all values)

    @:param data                datum
    @:param args                expects arguments (as list) with r (0 <= r < max_distance), max_distance, and key for MAC
    @:returns timestamp_tuple   four tuple with pseudonymized data
"""


def pseudo(input_time, args):
    if len(input_time) > 1024:
        print("Data too long.\n")
        return -1
    else:
        if len(args) != 3:
            print("Kerschbaum: Expected arguments: 3, given: " + str(len(args)))
            return -1
        else:
            r = int(args[0])
            max_distance = int(args[1])
	    key = str(args[2])

            unix_timestamp = int(time.mktime(time.strptime(input_time, '%Y-%m-%dT%H:%M:%SZ'))) - time.timezone

            lower_grid_point = max_distance * (math.floor(float(unix_timestamp - r)/max_distance)) + r
            upper_grid_point = max_distance * (math.ceil(float(unix_timestamp - r + 1)/max_distance)) + r

            mac_lgp = hmac.new(key, str(lower_grid_point), hashlib.sha512).hexdigest()
            mac_upg = hmac.new(key, str(upper_grid_point), hashlib.sha512).hexdigest()

            m = unix_timestamp - lower_grid_point
            v = unix_timestamp - upper_grid_point

            timestamp_data = str(mac_lgp) + "#" + str(m) + "#" + str(mac_upg) + "#" + str(v)
    return timestamp_data


""" Computes the distance from two pseudonymized datums

    @:param input_data1		pseudonymized datum
    @:param input_data2         pseudonymized datum
    @:returns distance          returns time distance as string in form: d h m s
"""

def get_distance(input_data1, input_data2):
    data1 = input_data1.split("#")
    data2 = input_data2.split("#")

    g1 = [str(data1[0]), str(data1[2])]
    g2 = [str(data2[0]), str(data2[2])]

    h1 = [float(data1[1]), float(data1[3])]
    h2 = [float(data2[1]), float(data2[3])]

    for i in range(len(g1)):
        for j in range(len(g2)):
            if g1[i] == g2[j]:
                # Case 2: ∃gc = g1[i] = g2[j]: δ = |h1[i] − h2[j]|
                distance_in_seconds = math.fabs(h1[i] - h2[j])
                days = int(math.floor(distance_in_seconds/60/60/24))
                hours = int(math.floor((distance_in_seconds-(days*60*60*24))/60/60))
                minutes = int(math.floor((distance_in_seconds-(days*60*60*24)-(hours*60*60))/60))
                seconds = int(math.floor((distance_in_seconds-(days*60*60*24)-(hours*60*60)-(minutes*60))))
                distance = str(days)+'d '+str(hours)+'h '+str(minutes)+'m '+str(seconds)+'s'
                return str(distance)

    # Case 1: g1[i] != g2[j] ∀i, j: δ > d
    print("Distance exceeds max_distance.")
    return False
