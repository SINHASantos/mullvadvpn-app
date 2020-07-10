//
//  MullvadRestAPI.swift
//  MullvadVPN
//
//  Created by pronebird on 10/07/2020.
//  Copyright © 2020 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Network

/// REST API v1 base URL
private let kRestBaseURL = URL(string: "https://api.mullvad.net/app/v1")!

/// Network request timeout in seconds
private let kNetworkTimeout: TimeInterval = 10

enum HttpMethod: String {
    case get = "GET"
    case post = "POST"
    case delete = "DELETE"
}

enum RestErrorCode: String {
    case invalidAccount = "INVALID_ACCOUNT"
    case keyLimitReached = "KEY_LIMIT_REACHED"
}

struct ServerErrorResponse: LocalizedError, Decodable {
    let code: String
    let error: String

    var errorDescription: String? {
        switch code {
        case RestErrorCode.keyLimitReached.rawValue:
            return NSLocalizedString("Too many public WireGuard keys", comment: "")
        case RestErrorCode.invalidAccount.rawValue:
            return NSLocalizedString("Invalid account", comment: "")
        default:
            return nil
        }
    }

    var recoverySuggestion: String? {
        switch code {
        case RestErrorCode.keyLimitReached.rawValue:
            return NSLocalizedString("Remove unused WireGuard keys", comment: "")
        default:
            return nil
        }
    }
}

enum RestError: Error {
    case encodeURLRequest(Error)
    case network(URLError)
    case server(ServerErrorResponse)
    case decodeErrorResponse(Error)
    case decodeSuccessResponse(Error)
}

protocol RestPayloadInjectable {
    func injectIntoRequest(_ request: inout URLRequest) throws
}

struct Payload<Value: Encodable>: RestPayloadInjectable {
    let payload: Value

    func injectIntoRequest(_ request: inout URLRequest) throws {
        request.httpBody = try makeJSONEncoder().encode(payload)
    }
}

struct AuthenticatedPayload<Payload: RestPayloadInjectable>: RestPayloadInjectable {
    let token: String
    let payload: Payload?

    init(token: String, payload: Payload) {
        self.token = token
        self.payload = payload
    }

    func injectIntoRequest(_ request: inout URLRequest) throws {
        request.addValue(token, forHTTPHeaderField: "Authentication")
        try payload?.injectIntoRequest(&request)
    }
}

extension AuthenticatedPayload where Payload == Never {
    init(token: String) {
        self.token = token
        self.payload = nil
    }
}

extension Never: RestPayloadInjectable {
    func injectIntoRequest(_ request: inout URLRequest) throws {}
}

struct RestEndpoint<Input, Output> where Input: RestPayloadInjectable, Output: Decodable {
    let endpointURL: URL
    let httpMethod: HttpMethod

    func makeURLRequest(payload: Input) -> Result<URLRequest, RestError> {
        return makeURLRequestHelper(payload: payload)
    }

    func dataTask(session: URLSession, payload: Input, completionHandler: @escaping (Result<Output, RestError>) -> Void) -> Result<URLSessionDataTask, RestError> {
        return makeURLRequestHelper(payload: payload).map { (request) -> URLSessionDataTask in
            Self.dataTask(session: session, request: request, completionHandler: completionHandler)
        }
    }

    private static func dataTask(session: URLSession, request: URLRequest, completionHandler: @escaping (Result<Output, RestError>) -> Void) -> URLSessionDataTask {
        return session.dataTask(with: request) { (responseData, urlResponse, error) in
            let result = Self.handleURLResponse(urlResponse, data: responseData, error: error)
            completionHandler(result)
        }
    }

    private static func handleURLResponse(_ urlResponse: URLResponse?, data: Data?, error: Error?) -> Result<Output, RestError> {
        if let error = error {
            let networkError = error as? URLError ?? URLError(.unknown)

            return .failure(.network(networkError))
        }

        guard let httpResponse = urlResponse as? HTTPURLResponse else {
            return .failure(.network(URLError(.unknown)))
        }

        if httpResponse.statusCode == 200 {
            return Self.decodeSuccessResponse(data ?? Data())
        } else {
            return Self.decodeErrorResponse(data ?? Data())
                .flatMap { (serverErrorResponse) -> Result<Output, RestError> in
                    return .failure(.server(serverErrorResponse))
            }
        }
    }

    private static func decodeErrorResponse(_ responseData: Data) -> Result<ServerErrorResponse, RestError> {
        return Result { () -> ServerErrorResponse in
            return try makeJSONDecoder().decode(ServerErrorResponse.self, from: responseData)
        }.mapError({ (error) -> RestError in
            return .decodeErrorResponse(error)
        })
    }

    private static func decodeSuccessResponse(_ responseData: Data) -> Result<Output, RestError> {
        return Result { () -> Output in
            return try makeJSONDecoder().decode(Output.self, from: responseData)
        }.mapError({ (error) -> RestError in
            return .decodeSuccessResponse(error)
        })
    }

    fileprivate func makeURLRequestHelper(payload: Input?) -> Result<URLRequest, RestError> {
        var request = URLRequest(
            url: endpointURL,
            cachePolicy: .useProtocolCachePolicy,
            timeoutInterval: kNetworkTimeout
        )
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpMethod = httpMethod.rawValue

        do {
            try payload?.injectIntoRequest(&request)

            return .success(request)
        } catch {
            return .failure(.encodeURLRequest(error))
        }
    }
}

extension RestEndpoint where Input == Never {
    func makeURLRequest() -> Result<URLRequest, RestError> {
        return makeURLRequestHelper(payload: nil)
    }

    func dataTask(session: URLSession, completionHandler: @escaping (Result<Output, RestError>) -> Void) -> Result<URLSessionTask, RestError> {
        return makeURLRequestHelper(payload: nil).map { (request) -> URLSessionTask in
            return session.dataTask(with: request) { (responseData, urlResponse, error) in
                let result = Self.handleURLResponse(urlResponse, data: responseData, error: error)
                completionHandler(result)
            }
        }
    }

}

struct AccountResponse: Decodable {
    let token: String
    let expires: Date
}

struct ServerLocation: Decodable {
    let country: String
    let city: String
    let latitude: Double
    let longitude: Double
}

struct ServerRelay: Decodable {
    let hostname: String
    let active: Bool
    let owned: Bool
    let location: String
    let provider: String
    let ipv4AddrIn: IPv4Address
    let weight: Int32
    let includeInCountry: Bool
}

struct ServerWireguardTunnel: Decodable {
    let ipv4Gateway: IPv4Address
    let ipv6Gateway: IPv6Address
    let publicKey: Data
    let portRanges: [ClosedRange<UInt16>]
    let relays: [ServerRelay]
}

struct ServerRelaysResponse: Decodable {
    let locations: [String: ServerLocation]
    let wireguard: [ServerWireguardTunnel]
}

class MullvadRest {

    func createAccount() -> RestEndpoint<Never, AccountResponse> {
        return RestEndpoint(
            endpointURL: kRestBaseURL.appendingPathComponent("accounts"),
            httpMethod: .post
        )
    }

    func getAccountExpiry() -> RestEndpoint<AuthenticatedPayload<Never>, AccountResponse> {
        return RestEndpoint(
            endpointURL: kRestBaseURL.appendingPathComponent("me"),
            httpMethod: .get
        )
    }

    func getRelayList() -> RestEndpoint<Never, ServerRelaysResponse> {
        return RestEndpoint(
            endpointURL: kRestBaseURL.appendingPathComponent("relays"),
            httpMethod: .get
        )
    }

}

func test() {
    let rest = MullvadRest()
    let a = rest.createAccount().makeURLRequest()
    let b = rest.getAccountExpiry().makeURLRequest(payload: .init(token: "1234"))

    let task = rest.createAccount().dataTask(session: .shared) { (result) in
        // todo:
    }

}

private func makeJSONEncoder() -> JSONEncoder {
    let encoder = JSONEncoder()
    encoder.keyEncodingStrategy = .convertToSnakeCase
    encoder.dateEncodingStrategy = .iso8601
    encoder.dataEncodingStrategy = .base64
    return encoder
}

private func makeJSONDecoder() -> JSONDecoder {
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    decoder.dateDecodingStrategy = .iso8601
    decoder.dataDecodingStrategy = .base64
    return decoder
}
