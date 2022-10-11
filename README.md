# GPlayLicenceValidator [![](https://jitpack.io/v/buggysofts-com/GPlayLicenceValidator.svg)](https://jitpack.io/#buggysofts-com/GPlayLicenceValidator)

Modified google play license validator library.

<br />

## Import
Add JitPack repository to your project level build.gradle file
```
...

allprojects {
    repositories {
        ...
        maven { url 'https://jitpack.io' }
    }
}
```
Or, in newer android projects, if you need to the add repository in settings.gradle file...
```
...

dependencyResolutionManagement {
    ...
    repositories {
        ...
        maven { url 'https://jitpack.io' }
    }
}
```
Finally, add this dependency to your app/module level build.gradle file
```
...

dependencies {
    ...
    implementation 'com.github.buggysofts-com:GPlayLicenceValidator:v1.0.4'
}
```
And you are done importing the library.

<br />

This is a secret library used only by the owner (which is me, Ragib - as long as i am alive). When creating downloadable artifacts, make this library public, as jitpack won't allow creating downloadable artifacts for a private repo. Make it private after creating downloadable artifact in jitpack.


### Happy coding!
