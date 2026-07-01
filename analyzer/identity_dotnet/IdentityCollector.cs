using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Text.Json;

namespace VulnScan.Identity;

public sealed record IdentityNode(string Id, string Kind, Dictionary<string, object?> Attributes);
public sealed record IdentityEdge(string Source, string Target, string Relation, string[] Permissions);

public sealed class LdapIdentityCollector
{
    public object Collect(string server, NetworkCredential credential, string searchBase)
    {
        using var connection = new LdapConnection(server) { Credential = credential, AuthType = AuthType.Negotiate };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.Bind();
        var request = new SearchRequest(searchBase, "(|(objectClass=user)(objectClass=group)(objectClass=computer))",
            SearchScope.Subtree, "distinguishedName", "objectClass", "memberOf", "userAccountControl",
            "servicePrincipalName", "msDS-AllowedToDelegateTo");
        var response = (SearchResponse)connection.SendRequest(request);
        var nodes = new List<IdentityNode>();
        var edges = new List<IdentityEdge>();
        foreach (SearchResultEntry entry in response.Entries)
        {
            string id = entry.DistinguishedName;
            var attrs = new Dictionary<string, object?> { ["dn"] = id };
            nodes.Add(new IdentityNode(id, "directory-object", attrs));
            if (entry.Attributes["memberOf"] is DirectoryAttribute groups)
                foreach (var group in groups.GetValues(typeof(string)))
                    edges.Add(new IdentityEdge(id, (string)group, "MemberOf", Array.Empty<string>()));
        }
        return new { nodes, edges, collectedAt = DateTimeOffset.UtcNow };
    }

    public string Serialize(object snapshot) => JsonSerializer.Serialize(snapshot,
        new JsonSerializerOptions { WriteIndented = true });
}
