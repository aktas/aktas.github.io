---
title: Graph Data Science With Networkx
published: true
---

In this article, I will explain the graph theory used in data science projects. We will use the networkx library in python for this. 

### [](#header-3)What is the graph theory? What is it used for?
Graph theory is a discipline based on structures represented by nodes called graphs and the edges connecting them.
Graph is a data structure consisting of nodes (nodes) and connections (edges) between these nodes. The graph class provides a set of features and functions for creating, manipulating, and analyzing graphs. These functions can be used for operations such as analyzing the structure of a graph, applying algorithms such as the shortest path algorithm, drawing the graph, or manipulating data on the graph.

### [](#header-3)How to use?
First we need to install the required library.

```python
pip3 install networkx
```
Now we can create an empty graph.
```python
import networkx as nx
G = nx.Graph()
```
We have an empty graph named G. We can use many self-defined methods with this graph object. Now let's add our nodes. In this example, I will denote our nodes with one letter each.
```python
import networkx as nx
G = nx.Graph()
G.add_node('A')                # We can add nodes one by one.
G.add_nodes_from(['B','C'])    # We can also get the nodes from an array.
```
Now let's add our connections.
```python
import networkx as nx
G = nx.Graph()
G.add_node('A')              
G.add_nodes_from(['B','C'])

G.add_edge('A','B')                     
G.add_edges_from([('B','C'),('A','C')])
```
Now let's plot the graph we created using the matplotlib library.
```python
import networkx as nx
G = nx.Graph()
G.add_node('A')              
G.add_nodes_from(['B','C'])

G.add_edge('A','B')                     
G.add_edges_from([('B','C'),('A','C')])

nx.draw(G, with_labels=True)
plt.show()
```
