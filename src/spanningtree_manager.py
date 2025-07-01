from config import TREE


class SpanningTree:
    def __init__(self, topology):
        self.topology = topology
        self.root = 's1'  # Root Bridge
        self.spanning_tree = {}  # Resulting spanning tree

    def build_tree(self):
        try:

            filtered_topology = {
                switch: {neighbor: port for neighbor, port in neighbors.items() if not neighbor.startswith('h')}
                for switch, neighbors in self.topology.items()}


            if self.root not in filtered_topology:
                raise KeyError(f"Root switch {self.root} not found in the topology.")
            # Initialize the spanning tree with the root switch
            self.spanning_tree = {switch: {} for switch in filtered_topology}
            print(f"{self.spanning_tree}")
            visited = set()
            edges = []

            # Start BFS from the root bridge
            visited.add(self.root)
            for neighbor, port in filtered_topology[self.root].items():
                edges.append((self.root, neighbor, port))
                print(f"{edges}")

            while edges:
                # Sort edges to ensure deterministic processing
                edges.sort(key=lambda x: x[1])
                parent, child, port = edges.pop(0)

                if child not in visited:
                    # Add edge to the spanning tree
                    self.spanning_tree[parent][child] = port
                    self.spanning_tree[child][parent] = filtered_topology[child][parent]

                    visited.add(child)

                    # Add neighbors of the newly visited switch
                    for neighbor, neighbor_port in filtered_topology[child].items():
                        if neighbor not in visited:
                            edges.append((child, neighbor, neighbor_port))

            # Print the spanning tree
            self.print_tree()

            # Update the global TREE variable
            global TREE
            TREE.clear()
            TREE.update(self.spanning_tree)
            print(f"spanning tree: {TREE}")

        except KeyError as e:
            print(f"KeyError: {e}. Check if all switches and connections are properly defined in the topology.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def print_tree(self):
        print("Spanning Tree:")
        for switch, connections in self.spanning_tree.items():
            for neighbor, port in connections.items():
                print(f"{switch} -({port})-> {neighbor}")

    def get_tree(self):
        return self.spanning_tree
