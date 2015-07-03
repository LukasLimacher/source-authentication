/************************************************************************/
/* $Id: MainP.cpp 65 2010-09-08 06:48:36Z yan.qi.asu $                                                                 */
/************************************************************************/

#include <limits>
#include <set>
#include <map>
#include <queue>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <algorithm>
#include "GraphElements.h"
#include "Graph.h"
#include "DijkstraShortestPathAlg.h"
#include "YenTopKShortestPathsAlg.h"

using namespace std;


/*void testDijkstraGraph()
{
	//Graph* my_graph_pt = new Graph("../data/example-graphMyTopo");
    Graph* my_graph_pt = new Graph;
    
	DijkstraShortestPathAlg shortest_path_alg(my_graph_pt);
	BasePath* result =
		shortest_path_alg.get_shortest_path(
			my_graph_pt->get_vertex(0), my_graph_pt->get_vertex(5));
	result->PrintOut(cout);
}*/


int main(...)
{
    //cout << "Dijkstra Test: " << endl;
	//testDijkstraGraph();
    
    //cout << "Yen Test: " << endl;
    //Read source, dest and max k from stdin
    int source, dest, kmax;
    cin >> source >> dest >> kmax;
    
    //Graph my_graph("../data/example-graphMyTopo");
    // Read Graph from stdin number of vertices and links: "from to cost"
    Graph my_graph;
    
    YenTopKShortestPathsAlg yenAlg(my_graph, my_graph.get_vertex(source),
                                   my_graph.get_vertex(dest));
    
    int i=0;
    while(yenAlg.has_next() && i < kmax)
    {
        ++i;
        yenAlg.next()->PrintOut(cout);
    }
}
