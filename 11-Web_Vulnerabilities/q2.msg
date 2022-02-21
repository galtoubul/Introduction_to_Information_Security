#announcements
/join #foo2 <script>
$.post("/post", {"channel": "#general-spam", "message": "Good Morning!", }).done(function(status) { status = JSON.parse(status); if (status.startsWith("#")) {SwitchChannel(status); $("#message")[0].value = "";  }     RefreshMessages(true);  }  );
</script>