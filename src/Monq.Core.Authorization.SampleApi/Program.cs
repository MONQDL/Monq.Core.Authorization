using Monq.Core.Authorization.SampleApi.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.ConfigureSMAuthentication(builder.Configuration);
builder.Services.AddControllers();
builder.Services.AddDistributedMemoryCache();

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseAuthentication();
app.UseAuthorization();
app.UseMonqAuthorization(app.Configuration);
app.MapControllers();

app.Run();
