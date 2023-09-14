module Main exposing (Msg(..), main, update, view)

import Array exposing (Array)
import Browser
import File exposing (File)
import Html exposing (Html, article, h1, h2, main_, p, text)


type alias Model =
    { requests : Array Request }


type alias Request =
    { crt : Result String String
    , mat : KeyMat
    }


type KeyMat
    = Csr String
    | Key String


init : () -> ( Model, Cmd Msg )
init _ =
    ( { requests = Array.empty }
    , Cmd.none
    )


type Msg
    = CsrsRequested
    | CsrsUploaded File (List File)


update : Msg -> Model -> ( Model, Cmd Msg )
update _ model =
    ( model, Cmd.none )


view : Model -> Browser.Document Msg
view model =
    { title = "Bifrost - Issue Certificates"
    , body =
        main_
            []
            [ h1 [] [ text "Certificate Issuer" ]
            , p [] [ text "Make some shit happen" ]
            ]
            :: (Array.toList <| Array.map viewRequest model.requests)
    }


viewRequest : Request -> Html Msg
viewRequest _ =
    article [] []


main : Program () Model Msg
main =
    Browser.document
        { init = init
        , subscriptions = \_ -> Sub.none
        , update = update
        , view = view
        }
