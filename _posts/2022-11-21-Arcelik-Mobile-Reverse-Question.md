---
title: Arçelik Mobile Reverse Question
published: true
---

![Arçelik Tv](/assets/tv.png)

In this article, I will explain the solution of the mobile question in the ctf event organized by Arçelik. You can download the apk file from [here](assets/RemoteWhiz.apk). I will show 2 different solutions. In the first solution I used the `jadx-gui` tool and `apktool`. In solution 2, I got the flag with `jadx-gui` and `frida`.

### [](#header-3)Solution 1
After opening the apk file with jadx-gui, we look at the first classes.

![RemoteWhiz classes](/assets/class.png)

When examining the login class, we see a control named Allow next to the username and password validation. The allow method always returns false. We will bypass this in solution 2. For now, we continue to examine the method and we see that the Remote.class has been imported.

![Login class](/assets/login.png)

When we go to the remote class, we see that the layout named activity_remote is used.

![Layout](/assets/layout.png)

We know that the layout named activity_remote is used. Now we have to decompile with apktool and look for this file.

```
find RemoteWhiz -iname activity_remote* 2>/dev/null
```

Output of the file:

```
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.widget.ConstraintLayout android:layout_width="fill_parent" android:layout_height="fill_parent"
  xmlns:android="http://schemas.android.com/apk/res/android" xmlns:app="http://schemas.android.com/apk/res-auto">
    <ImageView android:id="@id/imageView" android:layout_width="0.0dip" android:layout_height="wrap_content" android:layout_marginTop="193.0dip" android:layout_marginBottom="194.0dip" app:layout_constraintBottom_toBottomOf="parent" app:layout_constraintEnd_toEndOf="parent" app:layout_constraintStart_toStartOf="parent" app:layout_constraintTop_toTopOf="parent" app:srcCompat="@drawable/qr" />
</androidx.constraintlayout.widget.ConstraintLayout>
```
