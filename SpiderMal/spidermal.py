#!/usr/bin/env python

import requests, datetime, re, argparse, zipfile, os, sys, json
try:
    from MaltegoTransform import *
    transform = 1
except:
    transform = 0

__author__  = "Jeff White [karttoon]"
__email__   = "jwhite@paloaltonetworks.com"
__version__ = "1.0.3"
__date__    = "15DEC2016"

#################### [ API KEY ] ####################
pt_apikey   = ""
pt_user     = ""
#################### [ API KEY ] ####################

if pt_apikey == "":
    print "[=] API key not specified in", sys.argv[0]
    sys.exit(1)

graph_header = """<?xml version="1.1" encoding="UTF-8" standalone="no"?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:y="http://www.yworks.com/xml/graphml" xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns http://www.yworks.com/xml/schema/graphml/1.1/ygraphml.xsd">
<VersionInfo createdBy="Maltego Chlorine" subtitle="" version="3.6.0.6526"/>
<key for="port" id="d0" yfiles.type="portgraphics"/>
<key for="port" id="d1" yfiles.type="portgeometry"/>
<key for="port" id="d2" yfiles.type="portuserdata"/>
<key attr.name="MaltegoEntity" for="node" id="d3"/>
<key for="node" id="d4" yfiles.type="nodegraphics"/>
<key for="graphml" id="d5" yfiles.type="resources"/>
<key attr.name="MaltegoLink" for="edge" id="d6"/>
<key for="edge" id="d7" yfiles.type="edgegraphics"/>
<graph edgedefault="directed" id="G">"""

graph_footer = """</graph>
<data key="d5">
  <y:Resources/>
</data>
</graphml>"""

def pt_query(value, transform):
    url = 'https://api.passivetotal.org/v2/dns/passive'
    auth = (pt_user, pt_apikey)
    params = {'query': value}
    try:
        # Timeout can also act as a quasi break on hosting sites/large return values - remove the timeout if you really want the nodes
        pt_response = requests.get(url, params=params, auth=auth, timeout=60)
	if pt_response.status_code == 504: # Gateway Timeout error
		api_result = {'error': 'Gateway Timeout Error - 504'}
	else:
	        api_result = pt_response.json()
    except requests.exceptions.RequestException as error:
        api_result = {"error": error}
        if transform == 1:
            maltrans.addUIMessage("API Error. Too many resolves or connectivity issues - validate manually.", messageType="PartialError")
    return api_result

def date_convert(date, type): # Normalize the dates coming in from the various sources
    date_list = []
    if type == "PT": # PassiveTotal date format
        if date == "None":
            date = ['1970', '1', '1']
        else:
            date = (date.split(" ")[0]).split("-")
    if type == "user": # Dates supplied via CLI or Maltego
        date = date.split("-")
    for i in date:
        date_list.append(int(i))
    return datetime.date(date_list[0], date_list[1], date_list[2])

def build_ptlist(api_result): # Written for just PT at the moment, will need to rework for other APIs
    record_list = {}
    for record in api_result['results']:
        record_list[record['recordHash']] = [record['resolve'], record['firstSeen'], record['lastSeen']]
    return record_list

def build_node(value, type, number):
    node_body = '<node id="n' + str(number) + '">'
    node_body += """
<data key="d3">
<mtg:MaltegoEntity xmlns:mtg="http://maltego.paterva.com/xml/mtgx" id="""
    id_value = "malnode" + str(number)
    if type == "ip":
        node_body += '"' + id_value + '" type="maltego.IPv4Address">'
        node_body += """
<mtg:Properties>
<mtg:Property displayName="IP Address" hidden="false" name="ipv4-address" nullable="true" readonly="false" type="string">"""
    if type == "domain":
        node_body += '"' + id_value + '" type="maltego.Domain">'
        node_body += """
<mtg:Properties>
<mtg:Property displayName="Domain Name" hidden="false" name="fqdn" nullable="true" readonly="false" type="string">"""
    node_body += """
  <mtg:Value>""" + value + """</mtg:Value>"""
    node_body += """</mtg:Property>
</mtg:Properties>
</mtg:MaltegoEntity>
</data>
<data key="d4">
  <mtg:EntityRenderer xmlns:mtg="http://maltego.paterva.com/xml/mtgx">
  <mtg:Position x=""" + '"' + str(5 * number) + '"' + ' y="' + str(5 * number) + '"' + """/>
</mtg:EntityRenderer>
</data>
</node>"""
    return node_body

def build_edge(src_node, dst_node, number):
    edge_body = '<edge id="e' + str(number) + '" source="' + src_node + '" target="' + dst_node + '">'
    edge_body += """
<data key="d6">
<mtg:MaltegoLink xmlns:mtg="http://maltego.paterva.com/xml/mtgx" id="maledge""" + str(number) + '"' + """ type="maltego.link.manual-link">
</mtg:MaltegoLink>
  </data>
  <data key="d7">
    <mtg:LinkRenderer xmlns:mtg="http://maltego.paterva.com/xml/mtgx"/>
  </data>
</edge>"""
    return edge_body

def api_query(value, target_start, target_end, recursive, api, transform):
    # Initialize some values, lists, and dicts
    type = "user"
    count = 0
    final_list = {}
    record_list = {}
    value_stage = []
    processed_list = []
    while count < int(recursive): # Main iteration loop
        if transform == False: # Only print if transform is false (to STDOUT) otherwise Maltego will have an error
            print "    [@] Beginning recurse search number", str(count + 1) + "."
        if count == 0: # Set initial value first run
            value_list = [value]
        else:
            value_stage = []
        if value_list == []: # If all values popped out, don't let it keep iterating
            print "\t[=] *** No further values to lookup. ***"
            break
        val_len = len(value_list)
        val_count = 0
        while val_count < val_len:
            for value in value_list: # Iterate through each value
                if api == "PT": # PassiveTotal API Query
                    api_result = pt_query(value, transform)
                if "error" in api_result: # Print error if it timesout (generally due to a large value of resolutions being returned - seems 1K+ or # of queries
                    if transform == False:
                        print "\t[=] *** ERROR processing", value + ", too many resolves or connection issues. ***\n\t\t", api_result['error']
                    processed_list.append(value) # Once finished, add the value to the completed list
                    val_count += 1 # Increase the value count so we know where we're at
                    value_list = list(set(value_list)) # Unique the remaining value list
                    value_list.remove(value) # Remove just queried value
                    continue
                result_count = api_result['totalRecords']
                if result_count == 0: # If a domain has no resolutions or vice versa, remove from value list and break out of this value loop
                    if transform == False:
                        print "\t[=] *** No results found for", value, ". ***"
                    processed_list.append(value) # Once finished, add the value to the completed list
                    val_count += 1 # Increase the value count so we know where we're at
                    value_list = list(set(value_list)) # Unique the remaining value list
                    value_list.remove(value) # Remove just queried value
                    break
                if result_count >= 50: # If it returns a large number of results, most likely not wanted in the graph - prompt the user
                    if transform == False:
                        large_continue = raw_input("[%] " + str(result_count) + " results for " + value + " continue? [y/n] = ")
                        if large_continue.lower() == "n":
                            processed_list.append(value) # Once finished, add the value to the completed list
                            val_count += 1 # Increase the value count so we know where we're at
                            value_list = list(set(value_list)) # Unique the remaining value list
                            value_list.remove(value) # Remove just queried value
                            break
                if transform == False:
                    print "    [$]", str(result_count), "results for", value + "."
                # Try to match the type so it can do the correct lookup
                if re.match("^[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}$", api_result['queryValue']):
                    type = "ip"
                if re.match(".*\.[a-zA-Z]{2,63}$", api_result['queryValue']): # 63 for the new TLDs - just a general catch all
                    type = "domain"
                if type == "ip":
                    record_list = build_ptlist(api_result) # Query data - only setup for PT currently
                    for record in record_list: # For each domain that resolved to IP
                        ip_address = api_result['queryValue'] # IP record
                        domain = record_list[record][0] # Domain record
                        try: # Pull the PT Tag value for the domain
                            tag_value = api_result['results']['enrichment_map'][domain]['tags'][0]['value']
                        except:
                            tag_value = "Untagged"
                        try: # Pull the PT Dynamic value for the domain
                            dynamic_value = api_result['results']['enrichment_map'][domain]['dynamic']
                        except:
                            dynamic_value = "Unknown"
                        try: # Pull the PT Classification value for the domain
                            class_value = api_result['results']['enrichment_map'][domain]['classification']
                            if class_value == "":
                                class_value = "Unknown"
                        except:
                            class_value = "Unknown"
                        start_date = date_convert(record_list[record][1], api) # First seen
                        end_date = date_convert(record_list[record][2], api) # Last seen
                        date_overlap = min(target_end - start_date, end_date - target_start).days + 1
                        if date_overlap >= 1: # Validate target range falls within seen range
                            if ip_address not in final_list.keys(): # Check if the IP is already set, if not then add it
                                final_list[ip_address] = []
                            if domain not in final_list[ip_address]: # Check to make sure domain isn't tied to IP already
                                final_list[ip_address].append(domain) # Add IP:domain
                                if transform == False:
                                    if verbose == True:
                                        print "\t[=] MATCH: [start]", start_date, "[end]", end_date, "[value]", domain, "[class]", class_value, "[tag]", tag_value, "[dynamic]", dynamic_value
                                    else:
                                        print "\t[=] MATCH:", domain
                            if domain not in processed_list and domain not in value_stage: # Make sure the domain hasn't been processed yet
                                value_stage.append(domain) # Add domain to temp list for processing in next iteration
                if type == "domain":
                    record_list = build_ptlist(api_result) # Query data - only setup for PT currently
                    for record in record_list: # For each IP that resolved to domain
                        ip_address = record_list[record][0] # IP record
                        domain = api_result['queryValue']
                        try: # Pull the PT Tag value for the IP
                            tag_value = api_result['results']['enrichment_map'][ip_address]['tags'][0]['value']
                            if tag_value == "":
                                tag_value = "Untagged"
                        except:
                            tag_value = "Untagged"
                        try: # Pull the PT Sinkhole value for the IP
                            sinkhole_value = api_result['results']['enrichment_map'][ip_address]['sinkhole']
                        except:
                            sinkhole_value = "Unknown"
                        try: # Pull the PT Classification value for the IP
                            class_value = api_result['results']['enrichment_map'][ip_address]['classification']
                            if class_value == "":
                                class_value = "Unknown"
                        except:
                            class_value = "Unknown"
                        start_date = date_convert(record_list[record][1], api) # First seen
                        end_date = date_convert(record_list[record][2], api) # Last seen
                        date_overlap = min(target_end - start_date, end_date - target_start).days + 1
                        if date_overlap >= 1: # Validate target range falls within seen range
                            if ip_address not in final_list.keys(): # Validate that this IP entry doesnt exist
                                final_list[ip_address] = [] # Build blank IP entry
                            if ip_address not in processed_list and ip_address not in value_stage: # Validate IP hasn't been processed yet or set to run next iteration
                                final_list[ip_address].append(domain) # Add IP:domain
                                value_stage.append(ip_address) # Add IP to temp list for processing in next iteration
                                if transform == False:
                                    if verbose == True:
                                        print "\t[=] MATCH: [start]",start_date, "[end]", end_date, "[value]", ip_address, "[class]", class_value, "[tag]", tag_value, "[sinkhole]", sinkhole_value
                                    else:
                                        print "\t[=] MATCH:", ip_address
                processed_list.append(value) # Once finished, add the value to the completed list
                val_count += 1 # Increase the value count so we know where we're at
                value_list = list(set(value_list)) # Unique the remaining value list
                value_list.remove(value) # Remove just queried value
        count += 1 # Increase overall count by 1 to check againt recusrive level
        value_stage = list(set(value_stage)) # Unique the temp list (future value list) - returned results usually have a lot of duplicates due to temporal aspect
        for entry in value_stage: # Build next iteration loops value list
            value_list.append(entry)
    return final_list, type

def build_graph(final_list, filename):
    out_file = open('Graphs/Graph1.graphml', 'w')
    # Start building graph
    node_count = 0
    node_track = {}
    # Build necessary graph_header
    out_file.write(graph_header)
    # Build IP nodes
    for ip_entry in final_list:
        out_file.write(build_node(ip_entry, "ip", node_count))
        node_track["n" + str(node_count)] = ip_entry
        node_count += 1
    # Build Domain nodes
    domain_list = []
    for ip_entry in final_list:
        for domain in final_list[ip_entry]:
            domain_list.append(domain)
    domain_list = list(set(domain_list))
    for domain_entry in domain_list:
        out_file.write(build_node(domain_entry, "domain", node_count))
        node_track["n" + str(node_count)] = domain_entry
        node_count += 1
    # Build Edge links
    edge_count = 0
    for ip_entry in final_list: # Iterate through each IP
        for list_key, list_value in node_track.iteritems(): # Find node value for IP
            if list_value == ip_entry:
                src_node = list_key # Assign it to src_node for edge link
        for domain_entry in final_list[ip_entry]: # Find node value for domain
            for list_key, list_value in node_track.iteritems():
                if list_value == domain_entry:
                    dst_node = list_key # Assign it to dst_node for edge link
                    out_file.write(build_edge(src_node, dst_node, edge_count))
                    edge_count += 1
    # Build necessary graph footer
    out_file.write(graph_footer)
    out_file.close()

def zip_file(filename): # Builds the MTGX file by zipping the files in the directory up with the new Graph xml file
    zip_out = zipfile.ZipFile(filename, 'w')
    dir_include = ["Icons", "Graphs", "Entities"]
    for directory in dir_include:
        for root, dirs, files in os.walk(directory):
            for file in files:
                zip_out.write(os.path.join(root, file))
    zip_out.write('./', 'version_properties')
    zip_out.close()

def build_maltego(final_list, type, start_date, end_date): # Sends XML data to STDOUT that Maltego will catch, also ensures dates are returned for machines to keep the filter
    if type == "ip":
        for ip_entry in final_list:
            for domain_entry in final_list[ip_entry]:
                node = maltrans.addEntity("maltego.Domain", domain_entry)
                node.setType("maltego.Domain")
                node.addAdditionalFields("After", "Display Value", True, start_date)
                node.addAdditionalFields("Before", "Display Value", True, end_date)
    if type == "domain":
        for ip_entry in final_list:
            node = maltrans.addEntity("maltego.IPv4Address", ip_entry)
            node.setType("maltego.IPv4Address")
            node.addAdditionalFields("After", "Display Value", True, start_date)
            node.addAdditionalFields("Before", "Display Value", True, end_date)

def main():
    parser = argparse.ArgumentParser(description="Jumpstart Maltego graph of C2 infrastructure off domain or IP.", epilog="spidermal.py -l paloaltonetworks.com -s 2014-09-12 -e 2015-12-1 -r 2 -o pan.mgtx -a PT")
    parser.add_argument("-s", "--start", help="Start date for range; \"YYYY-MM-DD\".", metavar="YYYY-MM-DD")
    parser.add_argument("-e", "--end", help="End date for range; \"YYYY-MM-DD\".", metavar="YYYY-MM-DD")
    parser.add_argument("-l", "--lookup", help="Value you start search with.", required=True, metavar="IP|DOMAIN")
    parser.add_argument("-o", "--out", help="Output file name (will append \"mtgx\" if not present.", default="malgraph.mtgx", metavar="filename.mtgx")
    parser.add_argument("-r", "--recurse", help="Number of levels to recurse. Default is 1; be careful with hosting sites.", default=1, metavar="LEVEL")
    parser.add_argument("-a", "--api", help="Choose API to use. Default is PassiveTotal.", default="PT", choices=["PT"])
    parser.add_argument("-t", "--transform", help="Run in Maltego Transform mode (run from inside Maltego client).", action="store_true")
    parser.add_argument("-v", "--verbose", help="Print additional data (tags/class/dynamic fields).", action="store_true")
    args, unknown = parser.parse_known_args() # Make sure to collect the unknown arguments since Maltego will pass them in "#" format
    global verbose
    verbose = args.verbose
    target_start = datetime.date(1970, 1, 1) # Default start date for range
    target_end = datetime.date.today() # Default end date for range
    if args.transform == True:
        if transform == 0: # Check to make sure the MaltegoTransform.py file is there, otherwise notify user within Maltego
            print """<MaltegoMessage><MaltegoTransformResponseMessage><Entities></Entities><UIMessages><UIMessage MessageType="FatalError">MaltegoTransform.py Module Not Found!</UIMessage></UIMessages></MaltegoTransformResponseMessage></MaltegoMessage>"""
            sys.exit()
        unknownargs = unknown[0].split("#") # Peel off any dates sent by Maltego in the "Before" or "After" fields
        for argument in unknownargs:
            if argument.startswith("After"):
                target_start = date_convert(argument.split("=")[1], "user")
            elif argument.startswith("Before"):
                target_end = date_convert(argument.split("=")[1], "user")
            else:
                pass
        global maltrans # Build maltego transform to pipe data back if transform is selected
        maltrans = MaltegoTransform()
        final_list, type = api_query(args.lookup, target_start, target_end, "1", "PT", args.transform)
        build_maltego(final_list, type, str(target_start), str(target_end))
        maltrans.returnOutput()
    else:
        if args.start:
            target_start = date_convert(args.start, "user")
        if args.end:
            target_end = date_convert(args.end, "user")
        print "[+] Begining search for", args.lookup, "using", args.api, "API between", str(target_start), "and", str(target_end) + "."
        final_list, type = api_query(args.lookup, target_start, target_end, args.recurse, args.api, args.transform)
        print "[+] Finished API queries."
        print "[+] Building graph (nodes/edges)."
        build_graph(final_list, args.out)
        print "[+] Building Maltego file named", args.out + "."
        zip_file(args.out)

if __name__ == '__main__':
    main()
