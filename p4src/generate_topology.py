import json
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
from matplotlib.offsetbox import OffsetImage, AnnotationBbox

# Caricamento topologia
with open("topology.json") as f:
    data = json.load(f)

G = nx.Graph()
hosts = {}
switches = {}

# Aggiunta nodi
for host in data["hosts"]:
    G.add_node(host)
    hosts[host] = data["hosts"][host]

for switch in data["switches"]:
    G.add_node(switch)
    switches[switch] = {}

for link in data["links"]:
    node1, node2 = link
    node1 = node1.split("-")[0]
    node2 = node2.split("-")[0]
    G.add_edge(node1, node2)

# Posizioni nodi
pos = {}

switch_positions = {
    "s1": (-1.3, -2),
    "s2": (-1.7, 0),
    "s3": (1.7, 0),
    "s4": (1.3, -2),
    "s5": (0, 1)
}

host_positions = {
    "h1": (-3, -3),
    "h2": (-3, 0),
    "h3": (3, 0),
    "h4": (3, -3),
    "h5": (1, 2)
}

pos.update(switch_positions)
pos.update(host_positions)

# Aggiunta posizione controller fittizio sotto s4
pos["digest_controller"] = (1.3, -3.3)

# Funzioni
def add_node_image(ax, pos, node, img_path, zoom=0.12, offset=(0, 0)):
    img = mpimg.imread(img_path)
    img = OffsetImage(img, zoom=zoom)
    ab = AnnotationBbox(img, (pos[node][0] + offset[0], pos[node][1] + offset[1]), frameon=False, zorder=3)
    ax.add_artist(ab)

fig, ax = plt.subplots(figsize=(10, 8))

# Nodi invisibili
nx.draw_networkx_nodes(G, pos, node_size=0, ax=ax)

# Link standard in grigio
nx.draw_networkx_edges(G, pos, width=1.5, alpha=0.6, edge_color="gray", ax=ax)

# Immagini switch + p4 + WL
for switch in switches:
    if switch in pos:
        add_node_image(ax, pos, switch, "switch.png", zoom=0.18)
        add_node_image(ax, pos, switch, "p4.png", zoom=0.08, offset=(0, 0.2))

        if switch in ["s1", "s4", "s5"]:
            ax.text(
                pos[switch][0],
                pos[switch][1] - 0.35,
                "WL",
                fontsize=14,
                color="red",
                fontweight="bold",
                ha="center"
            )

# Host images
for host in hosts:
    if host in pos:
        add_node_image(ax, pos, host, "pc.png", zoom=0.12)

# Etichette nodi
labels = {node: node for node in G.nodes()}
labels["digest_controller"] = ""
nx.draw_networkx_labels(G, pos, labels, font_size=10, font_weight="bold", ax=ax)

plt.axis("off")
plt.savefig("topology_simple.pdf", format="pdf", dpi=300)
plt.show()

print("Topologia salvata come 'topology_simple.pdf'.")
