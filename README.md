# Tsuru2D

This is the server backend for the [Tsuru2D engine](https://github.com/Tsuru2D/Tsuru2D-engine).

## /create_user
```
Input: {
    "email": "bob@example.com",
    "password": "mypassword"
}

Output: {
    "success": true,
    "auth_token": "83d2867b60ee4eeb86c24214f734bce5"
}
```

## /login
```
Input: {
    "email": "bob@example.com",
    "password": "mypassword"
}

Output: {
    "success": true,
    "auth_token": "83d2867b60ee4eeb86c24214f734bce5"
}
```

## /logout
```
Input: {
    "auth_token": "83d2867b60ee4eeb86c24214f734bce5"
}

Output: {
    "success": true
}
```

## /create_game
```
Input: {
    "game_package": "com.example.mygame"
}

Output: {
    "success": true
}
```

## /write_save
```
Input: {
    "auth_token": "83d2867b60ee4eeb86c24214f734bce5",
    "game_package": "com.example.mygame",
    "overwrite": true,
    "index": 1,
    "version": 1,
    "time", 1445706098,
    "scene_id": "R.scene.scene1",
    "frame_id": "frame1",
    "custom_state": {
        ...
    }
}

Output: {
    "success": true,
    "save_id": 123
}
```

## /delete_save
```
Input: {
    "auth_token": "83d2867b60ee4eeb86c24214f734bce5",
    "save_id": 123
}

Output: {
    "success": true
}
```

## /enumerate_saves
```
Input: {
    "auth_token": "83d2867b60ee4eeb86c24214f734bce5",
    "game_package": "com.example.mygame",
    "from_index": 1,
    "to_index": 20
}

Output: {
    "success": true,
    "saves": [
        {
            "save_id": 123
            "index": 1,
            "version": 1,
            "time", 1445706098,
            "scene_id": "R.scene.scene1",
            "frame_id": "frame1",
            "custom_state": {
                ...
            }
        },
        {
            ...
        }
    ]
}
```
