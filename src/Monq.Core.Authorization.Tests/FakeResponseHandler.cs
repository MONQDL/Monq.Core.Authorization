using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Monq.Core.Authorization.Tests;

public class FakeResponseHandler : HttpMessageHandler
{
    readonly Dictionary<Uri, HttpResponseMessage> _fakeResponses = new Dictionary<Uri, HttpResponseMessage>();

    public void AddFakeResponse(Uri uri, HttpResponseMessage responseMessage, string content)
    {
        responseMessage.Content = new StringContent(content);
        _fakeResponses.Add(uri, responseMessage);
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (_fakeResponses.ContainsKey(request.RequestUri))
        {
            return Task.FromResult(_fakeResponses[request.RequestUri]);
        }

        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound) { RequestMessage = request });
    }
}
