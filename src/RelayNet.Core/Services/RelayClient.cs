using RelayNet.Core.Networking;
using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;

namespace RelayNet.Core.Services
{
    /// <summary>
    /// Persistent client for connecting to a relay. 
    /// Handles connection lifecycle, handshake, and frame sending/receiving.
    /// Designed for dependency injection.
    /// </summary>
    public class RelayClient : IAsyncDisposable
    {
        private RelayConnection? _connection;
        private readonly string _host;
        private readonly int _port;
        private bool _connected; 

        public RelayClient(string host, int port)
        {
            _host = host;
            _port = port;
        }
        /// <summary>
        /// Connect and keep the TCP open.
        /// </summary>
        public async Task ConnectAsync(CancellationToken ct = default)
        {
            if (_connection != null) return;
            
            _connection = await RelayConnection.ConnectAsync(_host, _port);

            // Hadshake will go here
            // await _handshake.RunClientAsync(_connection,ct);
        }
        /// <summary>
        /// Sends a frame via the connection.
        /// </summary>
        public async Task SendFrameAsync(Frame frame, CancellationToken ct = default)
        {
            if (_connection == null)
            throw new InvalidOperationException("Not connected");

            await _connection.SendFrameAsync(frame, ct);
        }
        /// <summary>
        /// Reads a frame from the connection.
        /// </summary>
        public async Task<Frame> ReceiveFrameAsync(CancellationToken ct = default)
        {
            if (_connection == null)
                throw new InvalidOperationException("Not connected");

           return await _connection.ReceiveFrameAsync(ct);
        }

        /// <summary>
        /// Dispose the underlyning connection.
        /// </summary>  
        public async ValueTask DisposeAsync()
        { 
           if(_connection != null)
                await _connection.DisposeAsync();
           _connection = null;
        }
    }
}
