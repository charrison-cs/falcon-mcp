"""
Contains Falcon Forensics FQL filter resources.
"""

from falcon_mcp.common.fql import FQL_BASE_OPERATORS
from falcon_mcp.common.utils import generate_md_table

# List of tuples containing filter options data: (name, type, operators, description)
SEARCH_COLLECTIONS_FQL_FILTERS = [
    (
        "Name",
        "Type",
        "Operators",
        "Description"
    ),
    (
        "platform",
        "String",
        "Yes",
        """
        Collection platform. Valid values are: windows, mac and linux.

        Ex (exact): platform:'windows'
        """
    ),
    (
        "state",
        "String",
        "Yes",
        """
        Collection state. Valid values are: 
        pending   
		contacting
		running   
		cancelling
		cancelled  
		completed 
		error 
		expired
        all   

        Ex: state:'running'
        """
    ),
    (
        "aid",
        "String",
        "No",
        """
        Falcon sensor ID (32 hex characters).

        Ex: aid:'2617e3fcf0804945ba6389328f3444f4'
        """
    ),
    (
        "ffcid",
        "String",
        "No",
        """
        Forensics Collector ID (32 hex characters).

        Ex: ffcid:'2617e3fcf0804945ba6389328f3444f4'
        """
    ),
    (
        "config_id",
        "String",
        "No",
        """
        Forensics configuration ID (32 hex characters).

        Ex: config_id:'2617e3fcf0804945ba6389328f3444f4'
        """
    ),
    (
        "session_id",
        "String",
        "No",
        """
        Forensics collector session ID (32 hex characters).

        Ex: session_id:'2617e3fcf0804945ba6389328f3444f4'
        """
        ),
    (
        "priority",
        "Number",
        "Yes",
        """
        The priority of the collection, 0-10.

        Ex: priority:>'5'
        """
    ),
    (
        "collection_tag",
        "String",
        "Yes",
        """
        Collection collection tag, used for grouping.

        Ex (exact): collection_tag:'deepscan2026'
        Ex (substring): collection_tag:*'*Triage*'
        """
    ),
    (
        "updated_by",
        "String",
        "Yes",
        """
        Who or what the collection was last updated by".

        Ex: updated_by:john.doe@acme.com
        """
    ),
]

SEARCH_COLLECTORS_FQL_FILTERS = [
    (
        "Name",
        "Type",
        "Operators",
        "Description"
    ),
    (
        "platform",
        "String",
        "Yes",
        """
        Collector platform. Valid values are: windows, mac and linux.

        Ex (exact): platform:'windows'
        """
    ),
    (
        "state",
        "String",
        "Yes",
        """
        Collector state. Valid values are: 
        all
        offline
        pending
        inprogress
        deployed
        error
        online  

        Ex: state:'online'
        """
    ),
    (
        "aid",
        "String",
        "No",
        """
        Falcon sensor ID (32 hex characters).

        Ex: aid:'2617e3fcf0804945ba6389328f3444f4'
        """
    ),
    (
        "ffcid",
        "String",
        "No",
        """
        Forensics Collector ID (32 hex characters).

        Ex: ffcid:'2617e3fcf0804945ba6389328f3444f4'
        """
    ),
    (
        "session_id",
        "String",
        "No",
        """
        Forensics collector session ID (32 hex characters).

        Ex: session_id:'2617e3fcf0804945ba6389328f3444f4'
        """
    ),
]

SEARCH_CONFIGURATIONS_FQL_FILTERS = [
    (
        "Name",
        "Type",
        "Operators",
        "Description"
    ),
    (
        "platform",
        "String",
        "Yes",
        """
        Configuration platform. Valid values are: windows, mac and linux.

        Ex (exact): platform:'windows'
        """
    ),
    (
        "name",
        "String",
        "Yes",
        """
        Configuration name.
        
        Ex (exact): name:'LightTriageWindows'
        Ex (substring): name:*'*Deep*'
        """
    ),
    (
        "description",
        "String",
        "No",
        """
        Configuration description.
                
        Ex (exact): description:'Light Triage for Workstations'
        Ex (substring): description:*'*Servers*'
        """
    ),
]

SEARCH_COLLECTIONS_FQL_DOCUMENTATION = """
Falcon Query Language (FQL) - Search Forensics Collections Guide

""" + FQL_BASE_OPERATORS + """

=== falcon_search_collections FQL filter options ===

""" + generate_md_table(SEARCH_COLLECTIONS_FQL_FILTERS) + """

=== COMMON FILTER EXAMPLES ===
• Collections in progress: state:'inprogress'
• Collections with the same collection tag: collection_tag:'WindowsWorkstationsScan4232026'

"""

SEARCH_COLLECTORS_FQL_DOCUMENTATION = """
Falcon Query Language (FQL) - Search Forensics Collectors Guide

""" + FQL_BASE_OPERATORS + """

=== falcon_search_collectors FQL filter options ===

""" + generate_md_table(SEARCH_COLLECTORS_FQL_FILTERS) + """

=== COMMON FILTER EXAMPLES ===
• Online collectors: state:'online'
• Offline collectors of a given platform: state:'online'+platform:'linux'

"""

SEARCH_CONFIGURATIONS_FQL_DOCUMENTATION = """
Falcon Query Language (FQL) - Search Forensics Configurations Guide

""" + FQL_BASE_OPERATORS + """

=== falcon_search_configurations FQL filter options ===

""" + generate_md_table(SEARCH_CONFIGURATIONS_FQL_FILTERS) + """

=== COMMON FILTER EXAMPLES ===
• All configurations for a given platform: platform:'windows'
• All configurations matching a name substring: name:*'*Registry*'

"""