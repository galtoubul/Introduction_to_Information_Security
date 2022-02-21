<html><head>
  <meta http-equiv="content-type" content="text/html; charset=UTF-8">
  <script src="https://code.jquery.com/jquery-3.5.1.min.js" integrity="sha256-9/aliU8dGd2tb6OSsuzixeV4y/faTqgFtohetphbbj0=" crossorigin="anonymous"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js" integrity="sha384-ApNbgh9B+Y1QKtv3Rn7W3mgPxhU9K/ScQsAP7hUibX39j7fakFPskvXusvfa0b4Q" crossorigin="anonymous"></script>
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js" integrity="sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl" crossorigin="anonymous"></script>
  <link rel="stylesheet" href="/static/custom.css">
  <script type="text/javascript" src="/static/code.js"></script>
  <title>Slack-Off @ NSK</title>
  <script type="text/javascript">var username = "{{username}}";</script>
</head>

<body>
  <div class="container">
  <h1>Slack-off @ NSK</h1>
  <p>Welcome, {{name}} (<span id="username">{{username}}</span>@)! Not you? <a href="/logout">Click here</a> to log out.</p>
  <div class="alert alert-warning" id="waiting" role="alert">The page is still loading, please wait...</div>
  <div class="row">
    <div class="col-md-2">
      <h3>
        Channels
      </h3>
      <ul id="channel-area">
      </ul>
    </div>
    <div class="col-md-10">
      <h3>
        Current channel: <mark id="current-channel"></mark>
      </h3>
      <div id="message-area">
        Nothing here yet!
      </div>
    </div>
  </div>

  <div class="row">
    <div class="col-md-12">
      <form class="form-online" id="post" action="/post" method="post">
        <div class="form-group">
          <textarea class="form-control" id="message" name="message" placeholder="Your message here!"></textarea>
          <button type="submit" class="btn btn-default" id="submit">
            Submit
          </button>
        </div>
      </form>
    </div>
  </div>
</div>
</body>
</html>
