#!binbash

# Start the Mininet topology
#echo [] Starting Mininet topology...
sudo python3 topo.py &
TOPO_PID=$!
sleep 3  # Allow topology to initialize

# Run the server script on h2
#echo [] Starting the server on h2...
sudo mnexec -a $(sudo mnexec -x h2 echo $$) python3 server.py  server.txt &
SERVER_PID=$!

# Run the SYN flood attack on h1
#echo [] Starting the SYN flood attack on h1...
sudo mnexec -a $(sudo mnexec -x h1 echo $$) python3 synflood.py &
FLOOD_PID=$!

# Run the router detection script on r1
#echo [] Starting the detection script on r1...
sudo mnexec -a $(sudo mnexec -x r1 echo $$) python3 router.py &
ROUTER_PID=$!

# Wait for user to stop
#echo [] Press Ctrl+C to stop all processes.
trap echo '[] Stopping all processes...'; sudo kill $TOPO_PID $SERVER_PID $FLOOD_PID $ROUTER_PID; exit INT

# Keep the script running to manage background processes
wait
