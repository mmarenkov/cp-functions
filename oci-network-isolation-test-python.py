#
# hello-python version 1.0.
#
# Copyright (c) 2020 Oracle, Inc.  All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.
#

import io
import json
import oci

from fdk import response

#from oci.core import ComputeManagementClientCompositeOperations

def remove_nsg_rule(virtual_network_client, nsg_id, rule_id):
    remove_nsg_rule_response = virtual_network_client.remove_network_security_group_security_rules(
        nsg_id,
        oci.core.models.RemoveNetworkSecurityGroupSecurityRulesDetails(
            security_rule_ids=[rule_id])
    ).data
    return remove_nsg_rule_response

def delete_nsg(virtual_network_client, nsg_id):
    delete_nsg_response = virtual_network_client.delete_network_security_group(nsg_id).data
    return delete_nsg_response

def handler(ctx, data: io.BytesIO=None):
    print("start debug Function Test-network", flush=True)
    source = "source"
    resourceName = "resourceName"
    resourceId = "ocid1.securitylist.oc1.eu-zurich-1.aaaaaaaaapn6wzsjgwmd2gje4kgsw5k4pdpasxpnqa6d6wchg67oc4tvcypa"
    try:
        body = json.loads(data.getvalue())
        source = body["source"]
        resourceName = body["data"]["resourceName"]
        resourceId = body["data"]["resourceId"]
    except (Exception, ValueError) as ex:
        print(str(ex), flush=True)

    print("source = ", source, flush=True)
    print("resourceName = ", resourceName, flush=True)
    print("resourceId = ", resourceId, flush=True)

    signer = oci.auth.signers.get_resource_principals_signer()
    virtual_network_client = oci.core.VirtualNetworkClient(config={}, signer=signer)

    if resourceId.find("networksecuritygroup") != -1:
        nsg = virtual_network_client.get_network_security_group(resourceId).data
        nsg_rules = virtual_network_client.list_network_security_group_security_rules(resourceId).data
        
        for rule in nsg_rules:
            print("NSG rule id = ", rule.id, flush=True)
            print("NSG source CIDR = ", rule.source, flush=True)
            if rule.source.find("/32") == -1:
                remove_nsg_rule(virtual_network_client,resourceId,rule.id)
                print('NSG rule id {0} with source {1} was deleted'.format(rule.id, rule.source), flush=True)
                
        resp_new = virtual_network_client.list_network_security_group_security_rules(resourceId).data

    elif resourceId.find("securitylist") != -1:
        
        sl_data = virtual_network_client.get_security_list(resourceId).data
        print("sl display name = ", sl_data.display_name, flush=True)

        #remove bad ingress rules
        ingress_rules =  [rule for rule in sl_data.ingress_security_rules if rule.source.find("/32") != -1] 
        sl_data.ingress_security_rules = ingress_rules

        #update security list
        resp_update = virtual_network_client.update_security_list(resourceId, update_security_list_details=oci.core.models.UpdateSecurityListDetails(
            defined_tags=sl_data.defined_tags,
            display_name=sl_data.display_name,
            egress_security_rules=sl_data.egress_security_rules,
            freeform_tags=sl_data.freeform_tags,
            ingress_security_rules=sl_data.ingress_security_rules))

        #get updated security list rules
        resp_new = virtual_network_client.get_security_list(resourceId).data

    return response.Response(
        ctx, response_data=resp_new,
        headers={"Content-Type": "application/json"}
    )