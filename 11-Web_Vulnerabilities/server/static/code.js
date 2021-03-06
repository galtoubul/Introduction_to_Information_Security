function Message(date, author, text, id) {
  this.date = date;
  this.author = author;
  this.text = text;
  this.id = id;
}

var WELCOME =
"Welcome! Please select a channel and let's start chatting!<br />" +
"<br />" +
"Note that:" +
"<ul>" +
"  <li>This channel is a dummy one - you can't post here</li>" +
"  <li>To see the set of supported commands, send the message <code>/?</code></li>" +
"  <li>Basic html is supported - you can use:" +
"    <ul>" +
"      <li><b>Bold</b> - &lt;b&gt;text&lt;/b&gt;</li>" +
"      <li><i>Italic</i> - &lt;i&gt;text&lt;/i&gt;</li>" +
"      <li><u>Underline</u> - &lt;u&gt;text&lt;/u&gt;</li>" +
"      <li><a>Links</a> - &lt;a href='target'&gt;text&lt/a&gt;</li>" +
"      <li>Images - &lt;img src='http://cats.com/cat.png' /&gt;</li>" +
"    </ul>" +
"  </li>" +
"  <li><b style='color: #dc3545'>To reset the exercise (logout + delete messages!) click <a href='/reset'>here</a></b></li>" +
"</ul>"
;
var LONELY = "You're the first one here! Sharing is caring - invite others!";

var db = {
  '#system': [
    new Message('', '', WELCOME, -1)
  ],
};
var shown_channels = [];
var current_channel = null;
var showing_lonely = false;

function ReceiveMessage(msg, channel, animate) {
  // Is this the first message in the channel?
  if (!(channel in db)) {
    db[channel] = [msg];
  } else {
    msgset = db[channel];
    // Is this a duplicate?
    if (msgset.length > 0 && msgset[msgset.length - 1].id >= msg.id) {
      return;
    }
    db[channel].push(msg);
  }
  
  if (channel == current_channel) {
    ShowMessage(msg, channel, animate);
  }
}

function ClearMessageDisplay() {
  $('#message-area').empty();
}

function insertChild(parent, child, animate) {
  if (animate) {
    $(child).css('display', 'none');
    $(child).appendTo(parent).show('slow');
  } else {
    parent.appendChild(child);
  }
}

function createElementHelper(type, opts) {
  var result = document.createElement(type);
  opts = opts || {};
  if (opts.class) {
    result.setAttribute('class', opts.class);
  }
  if (opts.id) {
    result.setAttribute('id', opts.id);
  }
  if (opts.text) {
    result.innerText = opts.text;
  }
  if (opts.html) {
    result.innerHTML = opts.html;
  }
  if (opts.child) {
    result.appendChild(opts.child);
  }
  if (opts.parent) {
    opts.parent.appendChild(result);
  }
  return result;
}

function AddToMessageArea(element, animate) {
  var wrapper = createElementHelper(
    'div', {'class': 'row', 'child': element}
  );
  insertChild($('#message-area')[0], wrapper, animate);
}

function ShowMessage(msg, channel, animate) {
  if (showing_lonely) {
    // Clear away the empty message
    ClearMessageDisplay();
    showing_lonely = false;
  }
  // <div class="col-md-10 message" id="msg-ID">
  //   <strong>USER</strong> | <em>TIME</em>
  //   <p>MESSAGE</p>
  // </div>
  var base = createElementHelper(
    'div', {'class': 'col-md-12 message', 'id': 'msg-' + msg.id}
  );
  if (msg.author) {
		base.appendChild(
			createElementHelper('strong', {'text': msg.author})
		);
		base.appendChild(
			document.createTextNode(' | ')
		);
  }
  if (msg.date) {
		base.appendChild(
			createElementHelper('em', {'text': msg.date})
		);
	}
  base.appendChild(
    createElementHelper('p', {'html': msg.text})
  );
  AddToMessageArea(base, animate);
}


function SwitchChannel(channel) {
  current_channel = channel;
  ClearMessageDisplay();
  // If there are no messages yet
  if (!db[channel] || db[channel].length == 0) {
    ShowMessage(new Message('', '', LONELY, -1), channel);
    showing_lonely = true;
  }
  // Otherwise show the existing  
  else {
    for (var i = 0; i < db[channel].length; ++i) {
      ShowMessage(db[channel][i], channel, false);
    }
  }
  window.location.hash = channel;
  $('#current-channel').text(channel);
  $('#submit').prop('disabled', channel == '#system');
}

function SwitchChannelCallback(source) {
  // var source = event.target || event.srcElement;
  SwitchChannel(source.innerText);
}


function AddChannel(channel, animate) {
  if (shown_channels.indexOf(channel) == -1) {
    db[channel] = db[channel] || [];
    var bullet = createElementHelper('li');
    var link = createElementHelper('a', {
      'html': channel,
      'parent': bullet
    });
    link.setAttribute('href', 'javascript:void(0)');
    link.addEventListener('click', function() { SwitchChannel(channel) });
    insertChild($('#channel-area')[0], bullet, animate);
    shown_channels.push(channel);
  }
}

function PostMessage() {
  $.post("/post", {
    'channel': current_channel,
    'message': $('#message')[0].value,
  }).done(function(status) {
    status = JSON.parse(status);
    if (status.startsWith('#')) {
      SwitchChannel(status);
      $('#message')[0].value = '';
    }
    else if (status != 'OK') {
      alert(status);
    }
    else {
      $('#message')[0].value = '';
      RefreshMessages(true);
    }
  });
}

function RefreshMessages(animate) {
  var channel = current_channel;
  if (current_channel == '#system') {
    return;
  }
  var last_id = -1;
  if ((channel in db) && db[channel].length > 0) {
    last_id = db[channel][db[channel].length - 1].id;
  }
  $.getJSON("/list_messages", {
    'channel': channel,
    'last_id': last_id
  }).done(function(data) {
    for (var i = 0; i < data.length; ++i) {
      var entity = data[i];
      ReceiveMessage(new Message(entity.date, entity.author, entity.text, entity.id), channel, animate);
    }
  });
}

function RefreshChannels(animate) {
  $.getJSON("/list_channels").done(function(data) {
    for (var i = 0; i < data.length; ++i) {
      var entity = data[i];
      AddChannel(data[i], animate);
    }
  });
}


function Refresh() {
  RefreshChannels(true);
  RefreshMessages(true);
  setTimeout(Refresh, 1500);
  $('#waiting').hide('slow');
}

$(document).ready(function() {
  $('#post').submit(function() {
    PostMessage();
    return false;
  });
  AddChannel('#system');
  SwitchChannel(window.location.hash || '#system');
  Refresh();
});
